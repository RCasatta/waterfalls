use crate::{
    fetch::Client,
    server::{sign::sign_response, Error, State},
    store::Store,
    AddressesRequest, DescriptorRequest, TxSeen, WaterfallRequest, WaterfallResponse,
    WaterfallResponseV3,
};
use age::x25519::Identity;
use elements::{
    encode::{serialize, serialize_hex, Decodable},
    Address, AddressParams, BlockHash, Transaction, Txid,
};
use elements_miniscript::DescriptorPublicKey;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    header::{self, CACHE_CONTROL, CONTENT_TYPE},
    Method, Request, Response, StatusCode,
};
use prometheus::Encoder;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

use super::{encryption, sign::MsgSigAddress, Network};

const GAP_LIMIT: u32 = 20;
const MAX_BATCH: u32 = 50;
const MAX_ADDRESSES: u32 = GAP_LIMIT * MAX_BATCH;
const MAX_ADDRESS_LENGTH: usize = 100; // max characters for an address (excessive to be conservative)

// needed endpoint to make this self-contained for testing, in prod they should probably be never hit cause proxied by nginx
// https://waterfalls.liquidwebwallet.org/liquidtestnet/api/blocks/tip/hash
// https://waterfalls.liquidwebwallet.org/liquidtestnet/api/block/bddf520b05c7552dca87289a035043a5c434133b3d1bb07b255fb1a30592b2d4/header
// https://waterfalls.liquidwebwallet.org/liquidtestnet/api/tx/3fb1f808534a881cc16c10745a2b861c7b33e13cfe2f5bf3fc872fd943d0bfca/raw
// https://waterfalls.liquidwebwallet.org/liquidtestnet/api/block-height/1424507
pub async fn route(
    state: &Arc<State>,
    client: &Arc<Mutex<Client>>,
    req: Request<Incoming>,
    network: Network,
) -> Result<Response<Full<Bytes>>, Error> {
    let is_testnet_or_regtest =
        network == Network::LiquidTestnet || network == Network::ElementsRegtest;
    log::debug!("---> {req:?}");
    let res = match (req.method(), req.uri().path(), req.uri().query()) {
        (&Method::GET, "/v1/server_recipient", None) => {
            str_resp(state.key.to_public().to_string(), StatusCode::OK)
        }
        (&Method::GET, "/v1/server_address", None) => {
            str_resp(state.address().to_string(), StatusCode::OK)
        }
        (&Method::GET, "/v1/waterfalls", Some(query)) => {
            let inputs = parse_query(
                query,
                &state.key,
                is_testnet_or_regtest,
                state.max_addresses,
            )?;
            handle_waterfalls_req(state, inputs, false, false, false).await
        }
        (&Method::GET, "/v2/waterfalls", Some(query)) => {
            let inputs = parse_query(
                query,
                &state.key,
                is_testnet_or_regtest,
                state.max_addresses,
            )?;
            handle_waterfalls_req(state, inputs, true, false, false).await
        }
        (&Method::GET, "/v3/waterfalls", Some(query)) => {
            let inputs = parse_query(
                query,
                &state.key,
                is_testnet_or_regtest,
                state.max_addresses,
            )?;
            handle_waterfalls_req(state, inputs, true, true, false).await
        }
        (&Method::GET, "/v1/waterfalls.cbor", Some(query)) => {
            let inputs = parse_query(
                query,
                &state.key,
                is_testnet_or_regtest,
                state.max_addresses,
            )?;
            handle_waterfalls_req(state, inputs, false, false, true).await
        }
        (&Method::GET, "/v2/waterfalls.cbor", Some(query)) => {
            let inputs = parse_query(
                query,
                &state.key,
                is_testnet_or_regtest,
                state.max_addresses,
            )?;
            handle_waterfalls_req(state, inputs, true, false, true).await
        }
        (&Method::GET, "/v3/waterfalls.cbor", Some(query)) => {
            let inputs = parse_query(
                query,
                &state.key,
                is_testnet_or_regtest,
                state.max_addresses,
            )?;
            handle_waterfalls_req(state, inputs, true, true, true).await
        }
        (&Method::GET, "/v1/time_since_last_block", None) => {
            let ts = state.tip_timestamp().await;
            let s = match ts {
                Some(ts) => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|e| Error::String(e.to_string()))?;
                    let delta = now.as_secs().saturating_sub(ts as u64);
                    if delta > 600 {
                        "more than 10 minutes"
                    } else {
                        "less than 10 minutes"
                    }
                }
                None => "unknown",
            };
            str_resp(s.to_string(), StatusCode::OK)
        }
        (&Method::GET, "/blocks/tip/hash", None) => {
            let block_hash = state.tip_hash().await;
            block_hash_resp(block_hash)
        }
        (&Method::POST, "/tx", None) => {
            let whole_body = req
                .collect()
                .await
                .map_err(|e| Error::String(e.to_string()))?
                .to_bytes();
            let result = std::str::from_utf8(&whole_body)
                .map_err(|e| Error::String(e.to_string()))?
                .to_string();
            let tx_bytes = hex::decode(result).map_err(|e| Error::String(e.to_string()))?;
            let tx = Transaction::consensus_decode(&tx_bytes[..])
                .map_err(|e| Error::String(e.to_string()))?;
            let result = client.lock().await.broadcast(&tx).await;
            match result {
                Ok(txid) => str_resp(txid.to_string(), StatusCode::OK),
                Err(e) => {
                    log::warn!("broadcast failed: {e:?}");
                    str_resp(e.to_string(), StatusCode::BAD_REQUEST)
                }
            }
        }
        (&Method::GET, "/metrics", None) => {
            let encoder = prometheus::TextEncoder::new();

            let metric_families = prometheus::gather();
            let mut buffer = vec![];
            encoder
                .encode(&metric_families, &mut buffer)
                .map_err(|e| Error::String(format!("{e:?}")))?;
            any_resp(buffer, StatusCode::OK, Some("text/plain"), Some(5), None)
        }
        (&Method::GET, path, None) => {
            let mut s = path.split('/');
            match (s.next(), s.next(), s.next(), s.next(), s.next()) {
                (Some(""), Some("block-height"), Some(v), None, None) => {
                    let height: u32 = v.parse().map_err(|_| Error::CannotParseHeight)?;
                    let block_hash = state.block_hash(height).await;
                    block_hash_resp(block_hash)
                }
                //address/ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh/txs
                (Some(""), Some("address"), Some(addr), Some("txs"), None) => {
                    let addr = Address::from_str(addr)
                        .map_err(|e| Error::InvalidAddress(e.to_string()))?;

                    handle_single_address(state, &addr, network).await
                }

                (Some(""), Some("tx"), Some(v), Some("raw"), None) => {
                    let txid = Txid::from_str(v).map_err(|_| Error::InvalidTxid)?;
                    let tx = match client.lock().await.tx(txid).await {
                        Ok(tx) => tx,
                        Err(e) => {
                            log::warn!(
                                "Cannot find tx, is the node running and txindex=1 ?\n{e:?}"
                            );
                            return Err(Error::CannotFindTx);
                        }
                    };
                    let result = serialize(&tx);
                    any_resp(
                        result,
                        StatusCode::OK,
                        Some("application/octet-stream"),
                        Some(157784630),
                        None,
                    )
                }
                (Some(""), Some("block"), Some(v), Some("header"), None) => {
                    let block_hash = BlockHash::from_str(v).map_err(|_| Error::InvalidBlockHash)?;
                    let block = client
                        .lock()
                        .await
                        .block(block_hash) // TODO should ask only header
                        .await
                        .map_err(|_| Error::CannotFindBlockHeader)?;
                    let result = serialize_hex(&block.header);
                    any_resp(
                        result.into_bytes(),
                        StatusCode::OK,
                        Some("text/plain"),
                        Some(157784630),
                        None,
                    )
                }
                _ => str_resp("endpoint not found".to_string(), StatusCode::NOT_FOUND),
            }
        }

        _ => str_resp("endpoint not found".to_string(), StatusCode::NOT_FOUND),
    };
    log::debug!("<--- {res:?}");
    res
}

fn block_hash_resp(
    block_hash: Option<elements::BlockHash>,
) -> Result<Response<Full<Bytes>>, Error> {
    match block_hash {
        Some(h) => str_resp(h.to_string(), StatusCode::OK),
        None => str_resp("cannot find it".to_string(), StatusCode::NOT_FOUND),
    }
}

fn parse_query(
    query: &str,
    key: &Identity,
    is_testnet_or_regtest: bool,
    max_addresses: usize,
) -> Result<WaterfallRequest, Error> {
    let mut params = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>();

    let page = params
        .get("page")
        .map(|e| e.parse().unwrap_or(0))
        .unwrap_or(0u16);

    let to_index = params
        .get("to_index")
        .map(|e| e.parse().unwrap_or(0))
        .unwrap_or(0u32);

    let descriptor = params.remove("descriptor");
    let addresses = params.remove("addresses");
    match (descriptor, addresses) {
        (Some(_), Some(_)) => Err(Error::CannotSpecifyBothDescriptorAndAddresses),
        (Some(desc_str), None) => {
            let desc_str = encryption::decrypt(&desc_str, key).unwrap_or(desc_str);

            let descriptor = desc_str
                .parse::<elements_miniscript::descriptor::Descriptor<DescriptorPublicKey>>()
                .map_err(|e| Error::String(e.to_string()))?;

            if is_testnet_or_regtest == desc_str.contains("xpub") {
                return Err(Error::WrongNetwork);
            }
            Ok(WaterfallRequest::Descriptor(DescriptorRequest {
                descriptor,
                page,
                to_index,
            }))
        }
        (None, Some(addresses)) => {
            let comma_count = addresses.matches(',').count();
            if addresses.len() > max_addresses * MAX_ADDRESS_LENGTH || comma_count > max_addresses {
                // early/fast length checks before parsing addresses which is expensive
                return Err(Error::TooManyAddresses);
            }
            let addresses = addresses
                .split(',')
                .map(|e| Address::from_str(e).map_err(|_| Error::InvalidAddress(e.to_string())))
                .collect::<Result<Vec<_>, _>>()?;
            if addresses.len() > max_addresses {
                return Err(Error::TooManyAddresses);
            }
            for a in addresses.iter() {
                if is_testnet_or_regtest == (a.params == &AddressParams::LIQUID) {
                    // TODO check if regtest or testnet
                    return Err(Error::WrongNetwork);
                }
                if a.blinding_pubkey.is_some() {
                    return Err(Error::AddressCannotBeBlinded);
                }
            }
            Ok(WaterfallRequest::Addresses(AddressesRequest {
                addresses,
                page,
            }))
        }
        (None, None) => Err(Error::AtLeastOneFieldMandatory),
    }
}

fn str_resp(s: String, status: StatusCode) -> Result<Response<Full<Bytes>>, Error> {
    any_resp(s.into_bytes(), status, Some("text/plain"), None, None)
}
fn any_resp(
    bytes: Vec<u8>,
    status: StatusCode,
    content: Option<&str>,
    cache: Option<u32>,
    msg_sig_adr: Option<MsgSigAddress>,
) -> Result<Response<Full<Bytes>>, Error> {
    let mut builder = Response::builder().status(status);
    if let Some(content) = content {
        builder = builder.header(CONTENT_TYPE, content)
    }
    let cache = cache.unwrap_or(5);
    builder = builder.header(CACHE_CONTROL, format!("public, max-age={cache}"));

    if let Some(msg_sig_adr) = msg_sig_adr {
        builder = builder.header("X-Content-Signature", msg_sig_adr.signature.to_string());
        builder = builder.header("X-Content-Digest", msg_sig_adr.message.to_string());
        builder = builder.header("X-Server-Address", msg_sig_adr.address.to_string());
    }

    builder
        .body(Full::new(bytes.into()))
        .map_err(|_| Error::Other)
}

async fn handle_single_address(
    state: &Arc<State>,
    address: &Address,
    network: Network,
) -> Result<Response<Full<Bytes>>, Error> {
    #[derive(Serialize)]
    struct EsploraTx {
        txid: elements::Txid,
        status: Status,
    }

    #[derive(Serialize)]
    struct Status {
        block_height: Option<i32>,
        block_hash: Option<BlockHash>,
    }

    // Check network compatibility
    if address.params != network.address_params() {
        return Err(Error::WrongNetwork);
    }

    let db = &state.store;
    let script_pubkey = address.script_pubkey();

    let script_hash = [db.hash(&script_pubkey)];
    let mut result: Vec<_> = db
        .get_history(&script_hash)
        .unwrap()
        .remove(0)
        .iter()
        .map(|e| EsploraTx {
            txid: e.txid,
            status: Status {
                block_height: Some(e.height as i32),
                block_hash: None,
            },
        })
        .collect();

    let seen_mempool = state.mempool.lock().await.seen(&script_hash).remove(0);
    result.extend(seen_mempool.iter().map(|e| EsploraTx {
        txid: *e,
        status: Status {
            block_height: Some(-1),
            block_hash: None,
        },
    }));

    {
        let blocks_hash_ts = state.blocks_hash_ts.lock().await;
        for esplora_tx in result.iter_mut() {
            if let Some(h) = esplora_tx.status.block_height {
                if h > 0 {
                    if let Some((block_hash, _)) = blocks_hash_ts.get(h as usize) {
                        esplora_tx.status.block_hash = Some(*block_hash)
                    }
                }
            }
        }
    }

    let result = serde_json::to_string(&result).unwrap();

    any_resp(
        result.into_bytes(),
        hyper::StatusCode::OK,
        Some("application/json"),
        Some(5),
        None,
    )
}

async fn handle_waterfalls_req(
    state: &Arc<State>,
    inputs: WaterfallRequest,
    with_tip: bool,
    v3: bool,
    cbor: bool,
) -> Result<Response<Full<Bytes>>, Error> {
    let db = &state.store;
    let start = Instant::now();
    let page = inputs.page();

    // TODO add label with batches?
    let timer = crate::WATERFALLS_HISTOGRAM
        .with_label_values(&["all"])
        .start_timer();

    let mut map = BTreeMap::new();

    match inputs {
        WaterfallRequest::Descriptor(DescriptorRequest {
            descriptor,
            page,
            to_index,
        }) => {
            for desc in descriptor.into_single_descriptors().unwrap().iter() {
                let is_single_address = !desc.has_wildcard();
                let mut result = Vec::with_capacity(GAP_LIMIT as usize); // At least
                for batch in 0..MAX_BATCH {
                    let mut scripts = Vec::with_capacity(GAP_LIMIT as usize);

                    let start = batch * GAP_LIMIT + page as u32 * MAX_ADDRESSES;
                    for index in start..start + GAP_LIMIT {
                        let l = desc.at_derivation_index(index).unwrap();
                        let script_pubkey = l.script_pubkey();
                        log::debug!("{}/{} {}", desc, index, script_pubkey);
                        scripts.push(db.hash(&script_pubkey));
                        if is_single_address {
                            break;
                        }
                    }

                    let is_last = find_scripts(state, db, &mut result, scripts).await;

                    if (is_last && start + GAP_LIMIT >= to_index) || is_single_address {
                        break;
                    }
                }
                map.insert(desc.to_string(), result);
            }
        }
        WaterfallRequest::Addresses(AddressesRequest { addresses, page: _ }) => {
            let mut scripts = Vec::with_capacity(addresses.len());
            for addr in addresses.iter() {
                scripts.push(db.hash(&addr.script_pubkey()));
            }
            let mut result = Vec::with_capacity(addresses.len());
            let _ = find_scripts(state, db, &mut result, scripts).await;
            map.insert("addresses".to_string(), result);
        }
    };

    // enrich with block hashes and timestamps
    {
        let blocks_hash_ts = state.blocks_hash_ts.lock().await;
        for v in map.values_mut() {
            for tx_seens in v.iter_mut() {
                for tx_seen in tx_seens.iter_mut() {
                    if tx_seen.height > 0 {
                        // unconfirmed has height 0, we don't want to map those to the genesis block
                        let (hash, ts) = blocks_hash_ts[tx_seen.height as usize];
                        tx_seen.block_hash = Some(hash);
                        tx_seen.block_timestamp = Some(ts);
                    }
                }
            }
        }
    }

    let elements: usize = map.values().map(|v| v.len()).sum();
    let tip = if with_tip {
        state.tip_hash().await
    } else {
        None
    };

    let waterfall_response = WaterfallResponse {
        txs_seen: map,
        page,
        tip,
    };
    let content = if cbor {
        "application/cbor"
    } else {
        "application/json"
    };
    let result = if v3 {
        let waterfall_response_v3: WaterfallResponseV3 =
            waterfall_response.try_into().expect("has tip");
        if cbor {
            let mut bytes = Vec::new();
            minicbor::encode(&waterfall_response_v3, &mut bytes).unwrap();
            bytes
        } else {
            serde_json::to_string(&waterfall_response_v3)
                .expect("does not contain a map with non-string keys")
                .as_bytes()
                .to_vec()
        }
    } else if cbor {
        let mut bytes = Vec::new();
        minicbor::encode(&waterfall_response, &mut bytes).unwrap();
        bytes
    } else {
        serde_json::to_string(&waterfall_response)
            .expect("does not contain a map with non-string keys")
            .as_bytes()
            .to_vec()
    };

    log::info!(
        "returning: {elements} elements, elapsed: {}ms",
        start.elapsed().as_millis()
    );
    crate::WATERFALLS_COUNTER.inc();
    timer.observe_duration();

    let m = sign_response(&state.secp, &state.wif_key, &result);
    let m = m.to_msg_sig_address(state.address());
    any_resp(
        result,
        hyper::StatusCode::OK,
        Some(content),
        Some(5),
        Some(m),
    )
}

async fn find_scripts(
    state: &Arc<State>,
    db: &crate::store::AnyStore,
    result: &mut Vec<Vec<TxSeen>>,
    scripts: Vec<u64>,
) -> bool {
    let mut seen_blockchain = db.get_history(&scripts).unwrap();
    let seen_mempool = state.mempool.lock().await.seen(&scripts);

    for (conf, unconf) in seen_blockchain.iter_mut().zip(seen_mempool.iter()) {
        for txid in unconf {
            conf.push(TxSeen::mempool(*txid, 0)) // TODO: compute vin/vout also for mempool
        }
    }
    let is_last = seen_blockchain.iter().all(|e| e.is_empty());
    result.extend(seen_blockchain);
    is_last
}

/// This function is used to wrap the route function so that it never returns an error but always a response
/// However, the signature must return Result anyway to be used in the service_fn
pub async fn infallible_route(
    state: &Arc<State>,
    client: &Arc<Mutex<Client>>,
    req: Request<Incoming>,
    network: Network,
    add_cors: bool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = match route(state, client, req, network).await {
        Ok(r) => r,
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(e.to_string().into()))
            .unwrap(),
    };

    // Add CORS headers if enabled
    if add_cors {
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST, OPTIONS".parse().unwrap(),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            "Content-Type".parse().unwrap(),
        );
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET_DESC: &str = "elwpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)#20ufqv7z";
    const TESTNET_DESC: &str = "elwpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)#v7pu3vak";

    #[test]
    fn test_parse_query() {
        // Test missing descriptor field
        let key = age::x25519::Identity::generate();
        let result = parse_query("", &key, false, 100);
        assert!(matches!(result, Err(Error::AtLeastOneFieldMandatory)));

        // Test invalid descriptor
        let result = parse_query("descriptor=invalid", &key, false, 100).unwrap_err();
        let not_an_element_desc = "Invalid descriptor: Not an Elements Descriptor".to_string();
        assert_eq!(result, Error::String(not_an_element_desc.clone()));

        // Test empty descriptor
        let result = parse_query("descriptor=", &key, false, 100).unwrap_err();
        assert_eq!(result, Error::String(not_an_element_desc));

        // Test valid clear descriptor
        let query = encode_query(MAINNET_DESC, None);
        let result = parse_query(&query, &key, false, 100).unwrap();
        assert_eq!(
            result.descriptor().unwrap().descriptor.to_string(),
            MAINNET_DESC
        );
        assert_eq!(result.page(), 0);

        // Test valid encrypted descriptor
        let encrypted = encryption::encrypt(MAINNET_DESC, key.to_public()).unwrap();
        let query = encode_query(&encrypted, None);
        let result = parse_query(&query, &key, false, 100).unwrap();
        assert_eq!(
            result.descriptor().unwrap().descriptor.to_string(),
            MAINNET_DESC
        );

        // Test with page parameter
        let query = encode_query(MAINNET_DESC, Some(5));
        let result = parse_query(&query, &key, false, 100).unwrap();
        assert_eq!(result.page(), 5);

        // Test wrong network (mainnet xpub on testnet) and then right network
        let query = encode_query(MAINNET_DESC, None);
        let result = parse_query(&query, &key, true, 100).unwrap_err();
        assert_eq!(result, Error::WrongNetwork);
        let result = parse_query(&query, &key, false, 100).unwrap();
        assert_eq!(
            result.descriptor().unwrap().descriptor.to_string(),
            MAINNET_DESC
        );

        // Test wrong network (testnet xpub on mainnet) and then right network
        let query = encode_query(TESTNET_DESC, None);
        let result = parse_query(&query, &key, false, 100).unwrap_err();
        assert_eq!(result, Error::WrongNetwork);
        let result = parse_query(&query, &key, true, 100).unwrap();
        assert_eq!(
            result.descriptor().unwrap().descriptor.to_string(),
            TESTNET_DESC
        );

        // Test Invalid Address
        let result = parse_query("addresses=ciao", &key, false, 100).unwrap_err();
        assert_eq!(result, Error::InvalidAddress("ciao".to_string()));

        // Test Valid mainnet Address
        let mainnet_address = "ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh";
        let result =
            parse_query(&format!("addresses={mainnet_address}"), &key, false, 100).unwrap();
        assert_eq!(result.addresses().unwrap().addresses.len(), 1);
        assert_eq!(
            result.addresses().unwrap().addresses[0].to_string(),
            mainnet_address
        );

        // Test Valid testnet Address
        let testnet_address = "tex1qv0s62sz6xnxf9d4qkvsnwqs5pz9k9q8dpp0q2h";
        let result = parse_query(&format!("addresses={testnet_address}"), &key, true, 100).unwrap();
        assert_eq!(result.addresses().unwrap().addresses.len(), 1);
        assert_eq!(
            result.addresses().unwrap().addresses[0].to_string(),
            testnet_address
        );

        // Test Invalid Address (blinding key)
        let result = parse_query("addresses=lq1qqgyxa469eaugae2sz3q8qzaqy0v57ecuekzyngfac5nw4z87yqskc5tp2wtueqq6am0x062zewkrl9lr0cqwvw0j9633xqe2e", &key, false, 100).unwrap_err();
        assert_eq!(result, Error::AddressCannotBeBlinded);

        // Test too many addresses
        let result = parse_query("addresses=ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh,ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh,ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh", &key, false, 2).unwrap_err();
        assert_eq!(result, Error::TooManyAddresses);

        // Test too many addresses, fast checks
        let result = parse_query("addresses=,,,", &key, false, 2).unwrap_err();
        assert_eq!(result, Error::TooManyAddresses);
        let long_str: String = "a".repeat(400);
        let query = format!("addresses={long_str}");
        let result = parse_query(&query, &key, false, 2).unwrap_err();
        assert_eq!(result, Error::TooManyAddresses);
    }

    fn encode_query(descriptor: &str, page: Option<u16>) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("descriptor", descriptor);
        if let Some(page) = page {
            serializer.append_pair("page", &page.to_string());
        }
        serializer.finish()
    }
}
