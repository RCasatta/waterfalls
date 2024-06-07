use crate::{db::TxSeen, state::State, Error};
use elements_miniscript::DescriptorPublicKey;
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    header::{CACHE_CONTROL, CONTENT_TYPE},
    Method, Request, Response, StatusCode,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};

const GAP_LIMIT: u32 = 20;
const MAX_BATCH: u32 = 50;
const MAX_ADDRESSES: u32 = GAP_LIMIT * MAX_BATCH;

struct Inputs {
    descriptor: String,

    /// Requested page, 0 if not specified
    /// The first returned index is equal to `page * 1000`
    /// The same page is used for all the descriptor (ie both external and internal)
    page: u16,
}

// needed endpoint to make this self-contained for testing, in prod they should probably be never hit cause proxied by nginx
// https://waterfall.liquidwebwallet.org/liquidtestnet/api/blocks/tip/hash
// https://waterfall.liquidwebwallet.org/liquidtestnet/api/block/bddf520b05c7552dca87289a035043a5c434133b3d1bb07b255fb1a30592b2d4/header
// https://waterfall.liquidwebwallet.org/liquidtestnet/api/tx/3fb1f808534a881cc16c10745a2b861c7b33e13cfe2f5bf3fc872fd943d0bfca/raw
// https://waterfall.liquidwebwallet.org/liquidtestnet/api/block-height/1424507

// curl --request POST --data 'elwpkh(xpub6DLHCiTPg67KE9ksCjNVpVHTRDHzhCSmoBTKzp2K4FxLQwQvvdNzuqxhK2f9gFVCN6Dori7j2JMLeDoB4VqswG7Et9tjqauAvbDmzF8NEPH/<0;1>/*)' http://localhost:3000/descriptor
// curl --request POST --data 'elsh(wpkh(xpub6BemYiVNp19ZzoiAAnu8oiwo7o4MGRDWgD55XFqSuQX9GJfsf4Y2Vq9Z1De1TEwEzqPyESUupP6EFy4daYGMHGb8kQXaYenREC88fHBkDR1/<0;1>/*))' http://waterfall.liquidwebwallet.org/liquid/descriptor | jq
pub(crate) async fn route(
    state: &Arc<State>,
    req: Request<Incoming>,
    is_testnet: bool,
) -> Result<Response<Full<Bytes>>, Error> {
    // println!("---> {req:?}");
    match (req.method(), req.uri().path(), req.uri().query()) {
        (&Method::GET, "/v1/waterfall", Some(query)) => {
            let inputs = parse_query(query)?;
            handle_waterfall_req(state, &inputs, is_testnet).await
        }
        (&Method::GET, "blocks/tip/hash", None) => {
            let block_hash = state.tip_hash().await;
            match block_hash {
                Some(h) => str_resp(h.to_string(), StatusCode::OK),
                None => str_resp("need to sync".to_string(), StatusCode::NOT_FOUND),
            }
        }
        _ => {
            let resp_body = match state.tip().await {
                Some(tip) => format!("tip height is {tip:?}"),
                None => "indexing need to start".to_owned(),
            };

            str_resp(resp_body, hyper::StatusCode::OK)
        }
    }
}

fn parse_query(query: &str) -> Result<Inputs, Error> {
    let mut params = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>();
    let descriptor = params
        .remove("descriptor")
        .ok_or(Error::DescriptorFieldMandatory)?;
    let page = params
        .get("page")
        .map(|e| e.parse().unwrap_or(0))
        .unwrap_or(0u16);

    Ok(Inputs { descriptor, page })
}

fn str_resp(s: String, status: StatusCode) -> Result<Response<Full<Bytes>>, Error> {
    any_resp(s, status, false, None)
}
fn any_resp(
    s: String,
    status: StatusCode,
    json: bool,
    cache: Option<u32>,
) -> Result<Response<Full<Bytes>>, Error> {
    let mut builder = Response::builder().status(status);
    if json {
        builder = builder.header(CONTENT_TYPE, "application/json")
    }
    if let Some(cache) = cache {
        builder = builder.header(CACHE_CONTROL, format!("public, max-age={cache}"))
    }
    Ok(builder
        .body(Full::new(s.into()))
        .map_err(|_| Error::Other)?)
}

#[derive(Serialize)]
struct Output {
    txs_seen: BTreeMap<String, Vec<Vec<TxSeen>>>,
    page: u16,
}

async fn handle_waterfall_req(
    state: &Arc<State>,
    inputs: &Inputs,
    is_testnet: bool,
) -> Result<Response<Full<Bytes>>, Error> {
    let desc_str = &inputs.descriptor;
    let db = &state.db;
    let start = Instant::now();
    match desc_str.parse::<elements_miniscript::descriptor::Descriptor<DescriptorPublicKey>>() {
        Ok(desc) => {
            if is_testnet == desc_str.contains("xpub") {
                return str_resp("Wrong network".to_string(), hyper::StatusCode::BAD_REQUEST);
            }
            let mut map = BTreeMap::new();
            for desc in desc.into_single_descriptors().unwrap().iter() {
                let mut result = Vec::with_capacity(GAP_LIMIT as usize); // At least
                for batch in 0..MAX_BATCH {
                    let mut scripts = Vec::with_capacity(GAP_LIMIT as usize);

                    let start = batch * GAP_LIMIT + inputs.page as u32 * MAX_ADDRESSES;
                    for index in start..start + GAP_LIMIT {
                        let l = desc.at_derivation_index(index).unwrap();
                        let script_pubkey = l.script_pubkey();
                        scripts.push(db.hash(&script_pubkey));
                    }
                    let mut seen_blockchain = db.get_history(&scripts).unwrap();
                    let seen_mempool = state.mempool.lock().await.seen(&scripts);

                    for (conf, unconf) in seen_blockchain.iter_mut().zip(seen_mempool.iter()) {
                        for txid in unconf {
                            conf.push(TxSeen::mempool(*txid))
                        }
                    }
                    let is_last = seen_blockchain.iter().all(|e| e.is_empty());
                    result.extend(seen_blockchain);

                    if is_last {
                        break;
                    }
                }
                map.insert(desc.to_string(), result);
            }

            // enrich with block hashes and timestamps
            {
                let blocks_hash_ts = state.blocks_hash_ts.lock().await;
                for v in map.values_mut() {
                    for tx_seens in v.iter_mut() {
                        for tx_seen in tx_seens.iter_mut() {
                            let (hash, ts) = blocks_hash_ts[tx_seen.height as usize];
                            tx_seen.block_hash = Some(hash);
                            tx_seen.block_timestamp = Some(ts);
                        }
                    }
                }
            }

            let elements: usize = map.iter().map(|(_, v)| v.len()).sum();
            let result = serde_json::to_string(&Output {
                txs_seen: map,
                page: inputs.page,
            })
            .unwrap();
            println!(
                "returning: {elements} elements, elapsed: {}ms",
                start.elapsed().as_millis()
            );
            any_resp(result, hyper::StatusCode::OK, true, Some(5))
        }
        Err(e) => str_resp(e.to_string(), hyper::StatusCode::BAD_REQUEST),
    }
}
