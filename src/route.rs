use crate::{db::TxSeen, state::State, Error};
use elements_miniscript::DescriptorPublicKey;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes, Incoming},
    header::{CACHE_CONTROL, CONTENT_TYPE},
    Method, Request, Response, StatusCode,
};
use std::{collections::BTreeMap, sync::Arc, time::Instant};

const GAP_LIMIT: u32 = 20;

// curl --request POST --data 'elwpkh(xpub6DLHCiTPg67KE9ksCjNVpVHTRDHzhCSmoBTKzp2K4FxLQwQvvdNzuqxhK2f9gFVCN6Dori7j2JMLeDoB4VqswG7Et9tjqauAvbDmzF8NEPH/<0;1>/*)' http://localhost:3000/descriptor
// curl --request POST --data 'elsh(wpkh(xpub6BemYiVNp19ZzoiAAnu8oiwo7o4MGRDWgD55XFqSuQX9GJfsf4Y2Vq9Z1De1TEwEzqPyESUupP6EFy4daYGMHGb8kQXaYenREC88fHBkDR1/<0;1>/*))' http://waterfall.liquidwebwallet.org/liquid/descriptor | jq
pub(crate) async fn route(
    state: &Arc<State>,
    req: Request<Incoming>,
    is_testnet: bool,
) -> Result<Response<Full<Bytes>>, Error> {
    let db = &state.db;
    // println!("---> {req:?}");
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/descriptor") => {
            let upper = req.body().size_hint().upper().unwrap_or(u64::MAX);
            if upper > 1024 * 64 {
                return str_resp(
                    "Body too big".to_string(),
                    hyper::StatusCode::PAYLOAD_TOO_LARGE,
                );
            }

            // Await the whole body to be collected into a single `Bytes`...
            let whole_body = req.collect().await.unwrap().to_bytes(); // TODO unwraps
            match std::str::from_utf8(whole_body.as_ref()) {
                Ok(desc) => handle_req(state, &desc, is_testnet).await,
                Err(_) => str_resp(
                    "Invalid utf8 string".to_string(),
                    hyper::StatusCode::BAD_REQUEST,
                ),
            }
        }
        _ => {
            let height = db.tip().unwrap();
            let hash = db.get_block_hash(height).unwrap().unwrap();
            let resp_body = format!("tip height is {} with hash {}", height, hash,);
            str_resp(resp_body, hyper::StatusCode::OK)
        }
    }
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

async fn handle_req(
    state: &Arc<State>,
    desc_str: &str,
    is_testnet: bool,
) -> Result<Response<Full<Bytes>>, Error> {
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
                for batch in 0.. {
                    let mut scripts = Vec::with_capacity(GAP_LIMIT as usize);

                    let start = batch * GAP_LIMIT;
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
            let result = serde_json::to_string(&map).unwrap();
            let elements: usize = map.iter().map(|(_, v)| v.len()).sum();
            println!(
                "returning: {elements} elements, elapsed: {}ms",
                start.elapsed().as_millis()
            );
            any_resp(result, hyper::StatusCode::OK, true, Some(5))
        }
        Err(e) => str_resp(e.to_string(), hyper::StatusCode::BAD_REQUEST),
    }
}
