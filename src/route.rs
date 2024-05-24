use std::{collections::BTreeMap, sync::Arc, time::Instant};

use elements_miniscript::DescriptorPublicKey;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    Method, Request, Response, StatusCode,
};
use tokio::sync::Mutex;

use crate::{
    db::{DBStore, TxSeen},
    mempool::Mempool,
    Error,
};

const GAP_LIMIT: u32 = 20;

// curl --request POST --data 'elwpkh(xpub6DLHCiTPg67KE9ksCjNVpVHTRDHzhCSmoBTKzp2K4FxLQwQvvdNzuqxhK2f9gFVCN6Dori7j2JMLeDoB4VqswG7Et9tjqauAvbDmzF8NEPH/<0;1>/*)' http://localhost:3000/descriptor

pub(crate) async fn route(
    db: &Arc<DBStore>,
    mempool: &Arc<Mutex<Mempool>>,
    req: Request<hyper::body::Incoming>,
    is_testnet: bool,
) -> Result<Response<Full<Bytes>>, Error> {
    println!("---> {req:?}");
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
                Ok(desc) => handle_req(db, mempool, &desc, is_testnet).await,
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
    let mut resp = Response::new(Full::new(s.into()));
    *resp.status_mut() = status;
    println!("<--- {resp:?}");
    Ok(resp)
}

async fn handle_req(
    db: &DBStore,
    mempool: &Arc<Mutex<Mempool>>,
    desc_str: &str,
    is_testnet: bool,
) -> Result<Response<Full<Bytes>>, Error> {
    let start = Instant::now();
    match desc_str.parse::<elements_miniscript::descriptor::Descriptor<DescriptorPublicKey>>() {
        Ok(desc) => {
            if is_testnet == desc_str.contains("tpub") {
                return Err(Error::WrongNetwork);
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
                    let seen_mempool = mempool.lock().await.seen(&scripts);

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
            println!("elapsed: {}ms", start.elapsed().as_millis());
            str_resp(result, hyper::StatusCode::OK)
        }
        Err(e) => str_resp(e.to_string(), hyper::StatusCode::BAD_REQUEST),
    }
}
