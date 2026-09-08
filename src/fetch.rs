use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use elements::{encode::Decodable, BlockHash};
use hyper::StatusCode;
use serde::Deserialize;
use serde_json::json;
use tokio::time::sleep;

use crate::{
    be::{self, Family},
    server::{Arguments, Network},
    store::BlockMeta,
};

/// Confirmation targets the same as Esplora exposes via /fee-estimates. It is used to batch query
/// node using `estimatesmartfee`.
const CONF_TARGETS: [u16; 28] = [
    1u16, 2u16, 3u16, 4u16, 5u16, 6u16, 7u16, 8u16, 9u16, 10u16, 11u16, 12u16, 13u16, 14u16, 15u16,
    16u16, 17u16, 18u16, 19u16, 20u16, 21u16, 22u16, 23u16, 24u16, 25u16, 144u16, 504u16, 1008u16,
];

#[derive(Debug)]
pub enum Error {
    TxNotFound(String, crate::be::Txid),
    BlockNotFound(String, BlockHash),
    BlockHeaderNotFound(String, BlockHash),
    UnexpectedStatus(String, StatusCode),
    BackendUnavailable(String),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TxNotFound(url, txid) => write!(f, "tx not found: {txid} for url {url}"),
            Error::BlockNotFound(url, hash) => write!(f, "block not found: {hash} for url {url}"),
            Error::BlockHeaderNotFound(url, hash) => {
                write!(f, "block header not found: {hash} for url {url}")
            }
            Error::UnexpectedStatus(url, status) => {
                write!(f, "unexpected status: {status} for url {url}")
            }
            Error::BackendUnavailable(message) => f.write_str(message),
        }
    }
}

pub struct Client {
    client: reqwest::Client,
    use_esplora: bool,
    base_url: String,

    /// even when `use_esplora` is false we use this for broadcasting because local node doesn't expose broadcasting via REST interface
    esplora_url: String,

    rpc_user_password: Option<String>,
}

const BS: &str = "https://blockstream.info";
const LOCAL: &str = "http://127.0.0.1";

impl Client {
    pub fn new(args: &Arguments) -> Result<Client> {
        args.is_valid()?;
        let rpc_user_password = if let Some(path) = args.rpc_user_password_file.as_ref() {
            if args.rpc_user_password.is_some() {
                log::warn!(
                    "--rpc-user-password is deprecated and ignored because --rpc-user-password-file is set"
                );
            }
            let content = std::fs::read_to_string(path).with_context(|| {
                format!("Failed to read rpc user password file {}", path.display())
            })?;
            Some(content.trim().to_string())
        } else if let Some(rpc_user_password) = args.rpc_user_password.as_ref() {
            log::warn!("--rpc-user-password is deprecated; use --rpc-user-password-file instead");
            Some(rpc_user_password.trim().to_string())
        } else {
            None
        };
        let esplora_url = match args.network {
            Network::Liquid => args
                .esplora_url
                .clone()
                .unwrap_or(format!("{BS}/liquid/api")),
            Network::LiquidTestnet => args
                .esplora_url
                .clone()
                .unwrap_or(format!("{BS}/liquidtestnet/api")),
            Network::ElementsRegtest => args.esplora_url.clone().unwrap_or(format!("{LOCAL}:3000")),

            Network::Bitcoin => args.esplora_url.clone().unwrap_or(format!("{BS}/api")),
            Network::BitcoinTestnet => args
                .esplora_url
                .clone()
                .unwrap_or(format!("{BS}/testnet/api")),
            Network::BitcoinTestnet4 => args
                .esplora_url
                .clone()
                .unwrap_or_else(|| "https://mempool.space/testnet4/api".to_string()),
            Network::BitcoinRegtest => args.esplora_url.clone().unwrap_or(format!("{LOCAL}:3000")),
            Network::BitcoinSignet => args
                .esplora_url
                .clone()
                .unwrap_or(format!("{BS}/signet/api")),
        };
        let use_esplora = args.use_esplora;
        let base_url = if use_esplora {
            esplora_url.clone()
        } else {
            let node_url = args.node_url.clone();
            let port = args.network.default_node_listen_port();
            node_url.unwrap_or(format!("{LOCAL}:{port}"))
        };
        log::info!("connecting to {base_url}");
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(args.request_timeout_seconds))
            .connect_timeout(Duration::from_secs(args.request_timeout_seconds)); // Connection establishment timeout
        if args.node_disable_conn_pool {
            if use_esplora {
                // The flag is node-only; applying it to Esplora would force a fresh
                // TCP + TLS handshake per request — a real regression — so ignore it
                // here, but make the ignored setting loud rather than silent.
                log::warn!(
                    "**********************************************************************\n\
                     * --node-disable-conn-pool (NODE_DISABLE_CONN_POOL) is set together   \n\
                     * with --use-esplora. This flag only affects the local node           \n\
                     * connection and is being IGNORED for the Esplora backend; keep-alive \n\
                     * pooling stays ENABLED.                                              \n\
                     **********************************************************************"
                );
            } else {
                // No keep-alive reuse: each request opens a fresh connection.
                builder = builder.pool_max_idle_per_host(0);
            }
        }
        let client = builder
            .build()
            .with_context(|| "Failed to create HTTP client with timeout")?;

        Ok(Client {
            client,
            use_esplora,
            base_url,
            esplora_url,
            rpc_user_password,
        })
    }

    pub async fn authenticated_rpc_preflight(&self) -> Result<()> {
        if self.use_esplora {
            return Ok(());
        }

        log::info!("checking rpc authentication against {}", self.base_url);
        let data = json!({
            "jsonrpc": "1.0",
            "id": "waterfalls-rpc-preflight",
            "method": "getnetworkinfo",
            "params": [],
        });
        let data = serde_json::to_string(&data)?;
        let response = self
            .client
            .post(self.rpc_url())
            .body(data)
            .send()
            .await
            .with_context(|| {
                format!("RPC authentication preflight failed for {}", self.base_url)
            })?;
        let status = response.status();
        let text = response.text().await?;
        if status != 200 {
            let message =
                format!("RPC authentication preflight failed with status:{status}, body is {text}");
            if retryable_status(status) {
                return Err(Error::BackendUnavailable(message).into());
            }
            anyhow::bail!(message);
        }

        let value: serde_json::Value = serde_json::from_str(&text).with_context(|| {
            format!("RPC authentication preflight returned invalid JSON: {text}")
        })?;
        if !value["error"].is_null() {
            if value["error"]["code"].as_i64() == Some(-28) {
                return Err(Error::BackendUnavailable(format!(
                    "RPC authentication preflight failed: {}",
                    value["error"]
                ))
                .into());
            }
            anyhow::bail!("RPC authentication preflight failed: {}", value["error"]);
        }
        if value.get("result").is_none() {
            anyhow::bail!("RPC authentication preflight returned JSON without result");
        }

        Ok(())
    }

    pub(crate) async fn validate_backend(
        &self,
        network: Network,
    ) -> std::result::Result<(), BackendValidationError> {
        self.authenticated_rpc_preflight()
            .await
            .map_err(BackendValidationError::classify)?;
        self.validate_network(network)
            .await
            .map_err(BackendValidationError::classify)
    }

    pub async fn validate_network(&self, network: Network) -> Result<()> {
        if self.use_esplora {
            let Some(expected) = expected_genesis_hash(network) else {
                log::warn!(
                    "skipping genesis validation for {network} because its genesis may be customized"
                );
                return Ok(());
            };
            let actual = self
                .block_hash(0)
                .await?
                .ok_or_else(|| anyhow!("backend did not return a genesis block for {network}"))?;
            validate_genesis_hash(network, expected, actual)
        } else {
            let chain_info = self
                .chain_info()
                .await?
                .ok_or_else(|| anyhow!("node did not return chain information for {network}"))?;
            validate_node_chain(network, &chain_info.chain)
        }
    }

    fn rpc_url(&self) -> String {
        let rpc_auth = self
            .rpc_user_password
            .as_ref()
            .expect("validated by Arguments");
        self.base_url
            .replace("http://", &format!("http://{rpc_auth}@",))
    }

    // `curl http://127.0.0.1:7041/rest/blockhashbyheight/0.hex`
    // GET /block-height/:height
    pub async fn block_hash(&self, height: u32) -> Result<Option<BlockHash>> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/block-height/{height}")
        } else {
            format!("{base}/rest/blockhashbyheight/{height}.hex",)
        };
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failing for {url}"))?;
        let status = response.status();
        if status == 200 {
            let hex = response
                .text()
                .await
                .with_context(|| format!("failing converting body to text for {url}"))?;
            let hex = hex.trim();
            Ok(Some(BlockHash::from_str(hex).with_context(|| {
                format!("failing converting {hex} to BlockHash")
            })?))
        } else if response.status() == 404 || response.status() == 503 {
            Ok(None)
        } else {
            error_panic!("{url} return unexpected status {status} for block_hash");
        }
    }

    /// GET /rest/chaininfo.json
    /// Returns chain information when connecting to a bitcoin node, None for esplora
    pub async fn chain_info(&self) -> Result<Option<ChainInfo>> {
        if self.use_esplora {
            return Ok(None);
        }

        let base = &self.base_url;
        let url = format!("{base}/rest/chaininfo.json");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failing for {url}"))?;

        let status = response.status();
        if status == 200 {
            let text = response
                .text()
                .await
                .with_context(|| format!("failing converting body to text for {url}"))?;
            let chain_info: ChainInfo = serde_json::from_str(&text)
                .with_context(|| format!("failing converting {text} to ChainInfo"))?;
            Ok(Some(chain_info))
        } else {
            Err(Error::UnexpectedStatus(url, status).into())
        }
    }

    /// GET /rest/block/<BLOCK-HASH>.<bin|hex|json>
    /// GET /block/:hash/raw
    pub async fn block(&self, hash: BlockHash, family: Family) -> Result<be::Block> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/block/{hash}/raw")
        } else {
            format!("{base}/rest/block/{hash}.bin",)
        };
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failing for {url}"))?;
        let status = resp.status();
        if status == 404 {
            return Err(Error::BlockNotFound(url, hash).into());
        } else if status != 200 {
            return Err(Error::UnexpectedStatus(url, status).into());
        }

        let bytes = resp.bytes().await?;

        match family {
            Family::Bitcoin => {
                let block = <bitcoin::Block as bitcoin::consensus::Decodable>::consensus_decode(
                    &mut bytes.as_ref(),
                )?;
                Ok(be::Block::Bitcoin(Box::new(block)))
            }
            Family::Elements => {
                let block = elements::Block::consensus_decode(bytes.as_ref())?;
                Ok(be::Block::Elements(Box::new(block)))
            }
        }
    }

    pub async fn block_header_json(
        &self,
        hash: BlockHash,
        family: Family,
    ) -> Result<Option<HeaderJson>> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/block/{hash}/status")
        } else {
            match family {
                // see https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockheaders
                Family::Bitcoin => format!("{base}/rest/headers/{hash}.json",),
                Family::Elements => format!("{base}/rest/headers/1/{hash}.json",), // pre bitcoin 24.0
            }
        };

        loop {
            let mut builder = self.client.get(&url);
            if family == Family::Bitcoin && !self.use_esplora {
                builder = builder.query(&[("count", "1")]);
            }
            let resp = builder
                .send()
                .await
                .with_context(|| format!("failing for {url}"))?;
            let status = resp.status();
            if status == 404 {
                log::warn!("block header json {hash} returned 404, reorg happened");
                return Ok(None);
            } else if status == 503 {
                log::warn!(
                    "block header {hash} returned 503 service unavailable, retrying in one second"
                );
                sleep(Duration::from_secs(1)).await;
                continue;
            } else if status != 200 {
                return Err(Error::UnexpectedStatus(url, status).into());
            }

            let text = resp.text().await?;
            let mut header: Vec<HeaderJson> = if self.use_esplora {
                let value: serde_json::Value = serde_json::from_str(&text)
                    .with_context(|| format!("failing converting {text} to Value"))?;
                let nextblockhash = value
                    .get("next_best")
                    .and_then(|v| v.as_str())
                    .and_then(|s| BlockHash::from_str(s).ok());
                vec![HeaderJson {
                    hash,
                    nextblockhash,
                }]
            } else {
                serde_json::from_str(&text)
                    .with_context(|| format!("failing converting {text} to Vec<HeaderJson>"))?
            };
            let header = match header.pop() {
                Some(header) => header,
                None => {
                    log::warn!("block header {hash} returned no header, reorg happened");
                    return Ok(None);
                }
            };
            return Ok(Some(header));
        }
    }

    /// GET /rest/headers/<BLOCK-HASH>.<bin|hex|json>
    /// GET /block/:hash/header
    pub async fn block_header(&self, hash: BlockHash, family: Family) -> Result<be::BlockHeader> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/block/{hash}/header")
        } else {
            match family {
                // see https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md#blockheaders
                Family::Bitcoin => format!("{base}/rest/headers/{hash}.bin",),
                Family::Elements => format!("{base}/rest/headers/1/{hash}.bin",), // pre bitcoin 24.0
            }
        };

        loop {
            let mut builder = self.client.get(&url);
            if family == Family::Bitcoin && !self.use_esplora {
                builder = builder.query(&[("count", "1")]);
            }
            let resp = builder
                .send()
                .await
                .with_context(|| format!("failing for {url}"))?;
            let status = resp.status();
            if status == 404 {
                log::warn!("block header {hash} returned 404, reorg happened");
                return Err(Error::BlockHeaderNotFound(url, hash).into());
            } else if status == 503 {
                log::warn!(
                    "block header {hash} returned 503 service unavailable, retrying in one second"
                );
                sleep(Duration::from_secs(1)).await;
                continue;
            } else if status != 200 {
                return Err(Error::UnexpectedStatus(url, status).into());
            }

            return match family {
                Family::Bitcoin => {
                    let bytes = if self.use_esplora {
                        let text = resp.text().await?;
                        hex_simd::decode_to_vec(text.as_bytes())
                            .map_err(|_| anyhow!("failing converting {text} to bytes"))?
                    } else {
                        resp.bytes().await?.to_vec()
                    };
                    let header =
                        <bitcoin::block::Header as bitcoin::consensus::Decodable>::consensus_decode(
                            &mut &bytes[..],
                        )?;
                    Ok(be::BlockHeader::Bitcoin(Box::new(header)))
                }
                Family::Elements => {
                    let bytes = if self.use_esplora {
                        let text = resp.text().await?;
                        hex_simd::decode_to_vec(text.as_bytes())
                            .map_err(|_| anyhow!("failing converting {text} to bytes"))?
                    } else {
                        resp.bytes().await?.to_vec()
                    };
                    let header = elements::BlockHeader::consensus_decode(&bytes[..])?;
                    Ok(be::BlockHeader::Elements(Box::new(header)))
                }
            };
        }
    }

    // curl http://127.0.0.1:7041/rest/
    // curl -s http://localhost:7041/rest/mempool/contents.json | jq
    // verbose false is not supported on liquid
    pub async fn mempool(&self, support_verbose: bool) -> Result<HashSet<crate::be::Txid>> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/mempool/txids")
        } else {
            format!("{base}/rest/mempool/contents.json")
        };

        let query = if support_verbose && !self.use_esplora {
            HashMap::from([("verbose".to_string(), "false".to_string())])
        } else {
            HashMap::new()
        };

        let resp = self
            .client
            .get(&url)
            .query(&query)
            .send()
            .await
            .with_context(|| {
                format!("failure opening {url}, is it correct and rest flag enabled in the node?")
            })?;
        let body_bytes = resp
            .bytes()
            .await
            .with_context(|| format!("failure reading {url} body in bytes"))?;

        Ok(if self.use_esplora {
            let content: HashSet<crate::be::Txid> = serde_json::from_slice(&body_bytes)
                .with_context(|| format!("failure converting {url} body in HashSet<Txid>"))?;
            content
        } else if support_verbose {
            serde_json::from_slice(&body_bytes)
                .with_context(|| format!("failure converting {url} body in HashSet<Txid> "))?
        } else {
            let content: HashMap<crate::be::Txid, Empty> = serde_json::from_slice(&body_bytes)
                .with_context(|| {
                    format!("failure converting {url} body in HashMap<Txid, Empty> ")
                })?;

            content.into_keys().collect()
        })
    }

    /// GET /rest/tx/<TX-HASH>.<bin|hex|json>
    pub async fn tx(&self, txid: crate::be::Txid, family: Family) -> Result<be::Transaction> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/tx/{txid}/raw")
        } else {
            format!("{base}/rest/tx/{txid}.bin")
        };

        loop {
            let resp = self.client.get(&url).send().await?;

            let status = resp.status();
            if status == 404 {
                return Err(Error::TxNotFound(url, txid).into());
            } else if status == 503 {
                log::error!("tx {txid} returned 503 service unavailable, retrying in one second");
                sleep(Duration::from_secs(1)).await;
                continue;
            } else if status != 200 {
                return Err(Error::UnexpectedStatus(url, status).into());
            }

            let bytes = resp.bytes().await?;

            return be::Transaction::from_bytes(bytes.as_ref(), family);
        }
    }

    /// POST /tx
    ///
    /// When using the node it must go through RPC interface because the node doesn't support broadcasting via REST
    /// We can't go full RPC for other methods because RPC doesn't return binary data
    ///
    pub async fn broadcast(&self, tx: &be::Transaction) -> Result<crate::be::Txid> {
        let tx_hex = tx.serialize_hex();

        let response = if self.use_esplora {
            let url = format!("{}/tx", &self.esplora_url);
            log::info!("broadcasting to {}", url);

            self.client.post(&url).body(tx_hex).send().await?
        } else {
            let url = self.rpc_url();
            log::info!("broadcasting to url {}", self.base_url);

            let data = json!({
                "jsonrpc":"1.0",
                "id": tx.txid(),
                "method": "sendrawtransaction",
                "params": [tx_hex],
            });
            log::trace!("data {data:?}");
            let data = serde_json::to_string(&data)?;

            self.client.post(&url).body(data).send().await?
        };
        let status = response.status();
        let text = response.text().await?;
        if status != 200 {
            anyhow::bail!("broadcast failed with status:{status}, body is {text}");
        }
        let txid = parse_broadcast_response(&text, self.use_esplora)?;
        assert_eq!(txid, tx.txid());
        Ok(txid)
    }

    pub(crate) async fn get_next(
        &self,
        last: &crate::store::BlockMeta,
        family: Family,
    ) -> Result<ChainStatus> {
        if let Some(header) = self.block_header_json(last.hash, family).await? {
            if let Some(next) = header.nextblockhash {
                let header = self.block_header(next, family).await?;
                Ok(ChainStatus::NewBlock(BlockMeta::new(
                    last.height + 1,
                    next,
                    header.time(),
                )))
            } else {
                Ok(ChainStatus::Tip)
            }
        } else {
            Ok(ChainStatus::Reorg)
        }
    }

    /// GET /fee-estimates
    ///
    /// Estimating using node requires RPC (estimatesmartfee) to avoid multiple requests for
    /// different targets with a single batch RPC request.
    pub async fn fee_estimates(&self) -> Result<HashMap<u16, f64>> {
        let result = if self.use_esplora {
            let url = format!("{}/fee-estimates", &self.esplora_url);
            log::info!("fetching fee estimates from {}", url);

            let response = self.client.get(&url).send().await?;
            let status = response.status();
            let text = response.text().await?;
            if !status.is_success() {
                let msg = format!("fee estimate fetch failed with status:{status}, body is {text}");
                log::warn!("{msg}");
                anyhow::bail!("{msg}");
            }

            serde_json::from_str::<HashMap<u16, f64>>(&text)?
        } else {
            let url = self.rpc_url();
            log::info!("fetching fee estimates from {}", self.base_url);

            let batch: Vec<serde_json::Value> = CONF_TARGETS
                .iter()
                .map(|t| {
                    json!({
                        "jsonrpc": "1.0",
                        "id": t,
                        "method": "estimatesmartfee",
                        "params": [t, "ECONOMICAL"],
                    })
                })
                .collect();
            let data = serde_json::to_string(&batch)?;

            let response = self.client.post(&url).body(data).send().await?;
            let status = response.status();
            let text = response.text().await?;
            if status != 200 {
                let msg = format!("fee estimate fetch failed with status:{status}, body is {text}");
                log::warn!("{msg}");
                anyhow::bail!("{msg}");
            }

            parse_fee_estimates_rpc_reply(&text)?
        };

        Ok(result)
    }
}

fn parse_fee_estimates_rpc_reply(text: &str) -> anyhow::Result<HashMap<u16, f64>> {
    let replies: Vec<serde_json::Value> = serde_json::from_str(text)?;
    Ok(replies
        .iter()
        .filter_map(|reply| {
            // in our request we are setting the id as the requested block target
            let target = reply["id"].as_u64().and_then(|id| u16::try_from(id).ok())?;
            if !reply["error"].is_null() {
                log::warn!(
                    "failed estimating fee for target {}: {:?}",
                    target,
                    reply["error"]
                );
                return None;
            }
            let result = &reply["result"];
            if !result["errors"].is_null() {
                log::warn!(
                    "failed estimating fee for target {}: {:?}",
                    target,
                    result["errors"]
                );
                return None;
            }
            let feerate = result["feerate"].as_f64()?;
            if feerate == -1f64 {
                log::warn!("not enough data to estimate fee for target {}", target);
                return None;
            }
            // Convert from BTC/kB to sat/vB
            Some((target, feerate * 100_000f64))
        })
        .collect())
}

fn parse_broadcast_response(text: &str, use_esplora: bool) -> anyhow::Result<crate::be::Txid> {
    if use_esplora {
        return crate::be::Txid::from_str(text.trim());
    }

    let value: serde_json::Value = serde_json::from_str(text)?;
    let txid_text = value
        .get("result")
        .ok_or(anyhow!("unexpected json without result"))?
        .as_str()
        .ok_or(anyhow!("unexpected non-string result"))?;
    crate::be::Txid::from_str(txid_text)
}

#[derive(Debug)]
pub enum ChainStatus {
    Tip,
    NewBlock(BlockMeta),
    Reorg,
}

#[derive(Deserialize)]
pub struct Empty {}

#[derive(Deserialize, Debug, Clone)]
pub struct HeaderJson {
    pub hash: BlockHash,
    pub nextblockhash: Option<BlockHash>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ChainInfo {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    pub bestblockhash: BlockHash,
}

fn validate_node_chain(network: Network, actual: &str) -> Result<()> {
    let expected = network.node_chain_name();
    if actual != expected {
        anyhow::bail!(
            "configured network {network} expects node chain {expected}, but backend reports {actual}"
        );
    }
    Ok(())
}

fn validate_genesis_hash(network: Network, expected: BlockHash, actual: BlockHash) -> Result<()> {
    if actual != expected {
        anyhow::bail!(
            "configured network {network} expects genesis block {expected}, but backend reports {actual}"
        );
    }
    Ok(())
}

fn expected_genesis_hash(network: Network) -> Option<BlockHash> {
    let bitcoin_network = match network {
        Network::Bitcoin => Some(bitcoin::Network::Bitcoin),
        Network::BitcoinTestnet => Some(bitcoin::Network::Testnet),
        Network::BitcoinTestnet4 => Some(bitcoin::Network::Testnet4),
        Network::BitcoinRegtest => Some(bitcoin::Network::Regtest),
        Network::BitcoinSignet => Some(bitcoin::Network::Signet),
        _ => None,
    };
    if let Some(network) = bitcoin_network {
        return bitcoin::constants::genesis_block(network)
            .block_hash()
            .to_string()
            .parse()
            .map(Some)
            .expect("bitcoin genesis hash must parse as an Elements block hash");
    }

    let hash = match network {
        Network::Liquid => "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003",
        Network::LiquidTestnet => {
            "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1"
        }
        Network::ElementsRegtest => return None,
        Network::Bitcoin
        | Network::BitcoinTestnet
        | Network::BitcoinTestnet4
        | Network::BitcoinRegtest
        | Network::BitcoinSignet => unreachable!("handled above"),
    };
    Some(hash.parse().expect("hardcoded genesis hash must parse"))
}

#[derive(Debug)]
pub(crate) struct BackendValidationError {
    error: anyhow::Error,
    retryable: bool,
}

impl BackendValidationError {
    pub(crate) fn is_retryable(&self) -> bool {
        self.retryable
    }

    pub(crate) fn unavailable(error: anyhow::Error) -> Self {
        Self {
            error,
            retryable: true,
        }
    }

    pub(crate) fn invalid(error: anyhow::Error) -> Self {
        Self {
            error,
            retryable: false,
        }
    }

    fn classify(error: anyhow::Error) -> Self {
        let retryable_request = error
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|error| !error.is_builder() && !error.is_redirect());
        let retryable_fetch = error
            .downcast_ref::<Error>()
            .is_some_and(|error| match error {
                Error::UnexpectedStatus(_, status) => retryable_status(*status),
                Error::BackendUnavailable(_) => true,
                _ => false,
            });
        if retryable_request || retryable_fetch {
            Self::unavailable(error)
        } else {
            Self::invalid(error)
        }
    }
}

impl std::fmt::Display for BackendValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{:#}", self.error)
        } else {
            self.error.fmt(f)
        }
    }
}

impl std::error::Error for BackendValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

fn retryable_status(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
}

#[cfg(test)]
mod test {
    use std::io::Write;

    #[cfg(any(feature = "esplora", feature = "synced_node"))]
    use elements::BlockHash;
    #[cfg(any(feature = "esplora", feature = "synced_node"))]
    use std::str::FromStr;

    use crate::server::{Arguments, Network};
    #[cfg(any(feature = "esplora", feature = "synced_node"))]
    use crate::Family;

    use super::{
        expected_genesis_hash, parse_fee_estimates_rpc_reply, validate_genesis_hash,
        validate_node_chain, BackendValidationError, Client,
    };

    #[cfg(feature = "esplora")]
    #[test]
    fn bitcoin_testnet4_default_esplora_url() {
        let args = Arguments {
            network: Network::BitcoinTestnet4,
            use_esplora: true,
            request_timeout_seconds: 1,
            ..Arguments::default()
        };
        let client = Client::new(&args).unwrap();
        assert_eq!(client.base_url, "https://mempool.space/testnet4/api");
    }

    #[test]
    fn configured_network_accepts_matching_node_chain() {
        for network in [
            Network::Liquid,
            Network::LiquidTestnet,
            Network::ElementsRegtest,
            Network::Bitcoin,
            Network::BitcoinTestnet,
            Network::BitcoinTestnet4,
            Network::BitcoinRegtest,
            Network::BitcoinSignet,
        ] {
            validate_node_chain(network, network.node_chain_name()).unwrap();
        }
    }

    #[test]
    fn configured_network_rejects_wrong_node_chain() {
        let err = validate_node_chain(Network::BitcoinTestnet, "testnet4").unwrap_err();
        assert!(err.to_string().contains("expects node chain test"));
        assert!(err.to_string().contains("backend reports testnet4"));
        assert!(!BackendValidationError::classify(err).is_retryable());
    }

    #[test]
    fn configured_network_accepts_matching_genesis() {
        for network in [
            Network::Liquid,
            Network::LiquidTestnet,
            Network::Bitcoin,
            Network::BitcoinTestnet,
            Network::BitcoinTestnet4,
            Network::BitcoinRegtest,
            Network::BitcoinSignet,
        ] {
            let expected = expected_genesis_hash(network).unwrap();
            validate_genesis_hash(network, expected, expected).unwrap();
        }
        assert_eq!(expected_genesis_hash(Network::ElementsRegtest), None);
    }

    #[test]
    fn configured_network_rejects_wrong_genesis() {
        let expected = expected_genesis_hash(Network::BitcoinTestnet).unwrap();
        let actual = expected_genesis_hash(Network::BitcoinSignet).unwrap();
        let err = validate_genesis_hash(Network::BitcoinTestnet, expected, actual).unwrap_err();
        assert!(err.to_string().contains("expects genesis block"));
        assert!(err.to_string().contains("backend reports"));
    }

    #[test]
    fn test_parse_fee_estimates_rpc_reply() {
        let json = r#"[
            {"id": 1, "error": null, "result": {"feerate": 0.00010000}},
            {"id": 2, "error": null, "result": {"feerate": 0.00005000}},
            {"id": 3, "error": null, "result": {"feerate": -1}},
            {"id": 4, "error": "some rpc error", "result": null},
            {"id": 5, "error": null, "result": {"errors": ["Insufficient data"]}},
            {"id": 6, "error": null, "result": {"feerate": 0.00002000}},
            {"id": 7, "error": null, "result": {}},
            {"id": 8, "error": null, "result": {"feerate": "not-a-number"}}
        ]"#;

        let result = parse_fee_estimates_rpc_reply(json).unwrap();

        // target 1: 0.00010000 BTC/kB == 10.0 sat/vB
        assert_eq!(result[&1], 10.0);
        // target 2: 0.00005000 BTC/kB == 5.0 sat/vB
        assert_eq!(result[&2], 5.0);
        // target 3: feerate == -1 -> filtered out
        assert!(!result.contains_key(&3));
        // target 4: has rpc error -> filtered out
        assert!(!result.contains_key(&4));
        // target 5: has result.errors -> filtered out
        assert!(!result.contains_key(&5));
        // target 6: 0.00002000 BTC/kB == 2.0 sat/vB
        assert_eq!(result[&6], 2.0);
        // target 7: feerate field missing -> filtered out
        assert!(!result.contains_key(&7));
        // target 8: feerate is not a number -> filtered out
        assert!(!result.contains_key(&8));
    }

    #[test]
    fn test_parse_fee_estimates_rpc_reply_invalid_input() {
        assert!(parse_fee_estimates_rpc_reply("not json").is_err());
        assert!(parse_fee_estimates_rpc_reply("{}").is_err());
        assert!(parse_fee_estimates_rpc_reply("").is_err());
        assert!(parse_fee_estimates_rpc_reply("42").is_err());
    }

    #[test]
    fn test_parse_fee_estimates_rpc_reply_out_of_order_batch() {
        let json = r#"[
            {"id": 6, "error": null, "result": {"feerate": 0.00002000}},
            {"id": 1, "error": null, "result": {"feerate": 0.00010000}},
            {"id": 2, "error": null, "result": {"feerate": 0.00005000}}
        ]"#;

        let result = parse_fee_estimates_rpc_reply(json).unwrap();

        assert_eq!(result[&1], 10.0);
        assert_eq!(result[&2], 5.0);
        assert_eq!(result[&6], 2.0);
    }

    /// Spawn a minimal HTTP/1.1 server on loopback that counts the TCP
    /// connections it accepts and answers every request with the same canned
    /// blockhash, keeping the connection alive for any follow-up requests.
    /// Returns the bound address and the accept counter.
    async fn spawn_counting_node() -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();

        tokio::spawn(async move {
            // A valid 64-hex blockhash so `block_hash` parses the body successfully.
            const HASH_HEX: &str =
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{HASH_HEX}",
                HASH_HEX.len()
            );
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let response = response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    // Serve each request on this connection until the client closes it,
                    // so a reused keep-alive connection is counted only once.
                    'conn: loop {
                        let mut req = Vec::new();
                        loop {
                            match socket.read(&mut buf).await {
                                Ok(0) | Err(_) => break 'conn, // client closed the connection
                                Ok(n) => {
                                    req.extend_from_slice(&buf[..n]);
                                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break; // full request headers received
                                    }
                                }
                            }
                        }
                        if socket.write_all(response.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        (addr, connections)
    }

    async fn spawn_rpc_preflight_node(
        status: &str,
        body: &str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_node_responses(&[(status, body)]).await
    }

    async fn spawn_node_responses(
        responses: &[(&str, &str)],
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responses: Vec<_> = responses
            .iter()
            .map(|(status, body)| (status.to_string(), body.to_string()))
            .collect();

        let handle = tokio::spawn(async move {
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        (addr, handle)
    }

    fn node_client(addr: std::net::SocketAddr, disable_conn_pool: bool) -> Client {
        node_client_url(format!("http://{addr}"), disable_conn_pool)
    }

    fn node_client_url(node_url: String, disable_conn_pool: bool) -> Client {
        let mut args = Arguments::default();
        args.network = Network::Bitcoin;
        args.use_esplora = false;
        args.node_url = Some(node_url);
        let mut rpc_user_password_file = tempfile::NamedTempFile::new().unwrap();
        write!(rpc_user_password_file, "user:pass").unwrap();
        args.rpc_user_password_file = Some(rpc_user_password_file.path().to_path_buf());
        args.request_timeout_seconds = 30; // Default::default() leaves this 0, which is_valid() rejects
        args.node_disable_conn_pool = disable_conn_pool;
        Client::new(&args).unwrap()
    }

    #[tokio::test]
    async fn test_authenticated_rpc_preflight_succeeds() {
        let (addr, handle) =
            spawn_rpc_preflight_node("200 OK", r#"{"result":{"version":280000},"error":null}"#)
                .await;
        let client = node_client(addr, false);

        client.authenticated_rpc_preflight().await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_authenticated_rpc_preflight_fails_on_unauthorized() {
        let (addr, handle) = spawn_rpc_preflight_node("401 Unauthorized", "").await;
        let client = node_client(addr, false);

        let err = client.authenticated_rpc_preflight().await.unwrap_err();
        assert!(err.to_string().contains("status:401 Unauthorized"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn backend_validation_retries_connection_failures() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = node_client(addr, false);

        let err = client.validate_backend(Network::Bitcoin).await.unwrap_err();

        assert!(err.is_retryable());
        assert!(err
            .to_string()
            .contains("RPC authentication preflight failed"));
    }

    #[tokio::test]
    async fn backend_validation_rejects_invalid_node_url() {
        let client = node_client_url("not a url".to_string(), false);

        let err = client.validate_backend(Network::Bitcoin).await.unwrap_err();

        assert!(!err.is_retryable());
        assert!(err
            .to_string()
            .contains("RPC authentication preflight failed"));
    }

    #[tokio::test]
    async fn backend_validation_rejects_bad_credentials() {
        let (addr, handle) = spawn_rpc_preflight_node("401 Unauthorized", "").await;
        let client = node_client(addr, false);

        let err = client.validate_backend(Network::Bitcoin).await.unwrap_err();

        assert!(!err.is_retryable());
        assert!(err.to_string().contains("status:401 Unauthorized"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn backend_validation_retries_service_unavailable() {
        let (addr, handle) = spawn_rpc_preflight_node("503 Service Unavailable", "").await;
        let client = node_client(addr, false);

        let err = client.validate_backend(Network::Bitcoin).await.unwrap_err();

        assert!(err.is_retryable());
        assert!(err.to_string().contains("status:503 Service Unavailable"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn backend_validation_retries_node_warmup() {
        let (addr, handle) = spawn_rpc_preflight_node(
            "200 OK",
            r#"{"result":null,"error":{"code":-28,"message":"Loading block index"}}"#,
        )
        .await;
        let client = node_client(addr, false);

        let err = client.validate_backend(Network::Bitcoin).await.unwrap_err();

        assert!(err.is_retryable());
        assert!(err.to_string().contains("Loading block index"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn backend_validation_retries_chain_info_unavailable() {
        let (addr, handle) = spawn_node_responses(&[
            ("200 OK", r#"{"result":{"version":280000},"error":null}"#),
            ("503 Service Unavailable", ""),
        ])
        .await;
        let client = node_client(addr, false);

        let err = client.validate_backend(Network::Bitcoin).await.unwrap_err();

        assert!(err.is_retryable());
        assert!(err.to_string().contains("503 Service Unavailable"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn backend_validation_rejects_wrong_node_network() {
        let (addr, handle) = spawn_node_responses(&[
            (
                "200 OK",
                r#"{"result":{"version":280000},"error":null}"#,
            ),
            (
                "200 OK",
                r#"{"chain":"signet","blocks":1,"headers":1,"bestblockhash":"00000008819873e925422c1ff0f99f7c85b01e6bffe137e43aeb8f5358f2a4db"}"#,
            ),
        ])
        .await;
        let client = node_client(addr, false);

        let err = client.validate_backend(Network::Bitcoin).await.unwrap_err();

        assert!(!err.is_retryable());
        assert!(err.to_string().contains("expects node chain main"));
        assert!(err.to_string().contains("backend reports signet"));
        handle.await.unwrap();
    }

    /// Default (pooled) behavior: sequential requests reuse a single keep-alive connection.
    #[tokio::test]
    async fn test_conn_pool_enabled_reuses_connection() {
        use std::sync::atomic::Ordering;

        let (addr, connections) = spawn_counting_node().await;
        let client = node_client(addr, false);

        for _ in 0..3 {
            client.block_hash(0).await.unwrap().unwrap();
        }

        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    /// With the pool disabled, every request establishes its own connection, so a
    /// locality-aware L4 proxy re-evaluates the upstream on each request instead of
    /// staying pinned to whichever backend the first connection landed on.
    #[tokio::test]
    async fn test_conn_pool_disabled_opens_fresh_connection_each_request() {
        use std::sync::atomic::Ordering;

        let (addr, connections) = spawn_counting_node().await;
        let client = node_client(addr, true);

        for _ in 0..3 {
            client.block_hash(0).await.unwrap().unwrap();
        }

        assert_eq!(connections.load(Ordering::SeqCst), 3);
    }

    #[cfg(feature = "esplora")]
    #[tokio::test]
    #[ignore = "connects to prod server"]
    async fn test_client_esplora() {
        let _ = env_logger::try_init();
        let mut args = Arguments {
            use_esplora: true,
            request_timeout_seconds: 30,
            ..Arguments::default()
        };
        for network in [
            Network::Bitcoin,
            Network::BitcoinTestnet4,
            Network::Liquid,
            Network::LiquidTestnet,
        ] {
            args.network = network;
            let client = Client::new(&args).unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            test(client, network).await;
        }
    }

    #[tokio::test]
    #[cfg(feature = "synced_node")]
    async fn test_client_local_liquid() {
        let client = init_client(Network::Liquid);
        test(client, Network::Liquid).await;
    }

    #[tokio::test]
    #[cfg(feature = "synced_node")]
    async fn test_client_local_liquid_testnet() {
        let client = init_client(Network::LiquidTestnet);
        test(client, Network::LiquidTestnet).await;
    }

    #[tokio::test]
    #[cfg(feature = "synced_node")]
    async fn test_client_local_bitcoin() {
        let client = init_client(Network::Bitcoin);
        test(client, Network::Bitcoin).await;
    }

    #[cfg(feature = "synced_node")]
    fn init_client(network: Network) -> Client {
        let args = Arguments {
            use_esplora: false,
            network,
            ..Arguments::default()
        };
        Client::new(&args).unwrap()
    }

    #[cfg(any(feature = "esplora", feature = "synced_node"))]
    async fn test(client: Client, network: Network) {
        let (genesis_hash, genesis_txid, another_txid) = match network {
            Network::Liquid => (
                "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003",
                "45de9fd4cb0f2a63b3afc68d26403f0d3c773d6cf2f42508bd8e7d7704f267d7",
                None,
            ),
            Network::LiquidTestnet => (
                "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1",
                "0471d2f856b3fdbc4397af272bee1660b77aaf9a4aeb86fdd96110ce00f2b158",
                None,
            ),
            Network::ElementsRegtest => (
                "c7af03b0774a3498a574902bd41045c1633fd40b69ca163345c5d9c78bfd6af7",
                "81c9570df1135a6bb7fb0f77a273561fddfd87bc62e7f265e94ffb01474ae578",
                None,
            ),
            Network::Bitcoin => (
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                Some("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"),
            ),
            Network::BitcoinTestnet => todo!(),
            Network::BitcoinTestnet4 => (
                "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
                "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e",
                None,
            ),
            Network::BitcoinRegtest => (
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                None,
            ),
            Network::BitcoinSignet => todo!(),
        };

        let genesis_hash = BlockHash::from_str(genesis_hash).unwrap();
        let genesis_txid = crate::be::Txid::from_str(genesis_txid).unwrap();

        let fetched = client.block_hash(0).await.unwrap().unwrap();
        assert_eq!(genesis_hash, fetched, "network:{network}");
        let genesis_block = client.block(genesis_hash, network.into()).await.unwrap();
        log::debug!("genesis_block: {genesis_block:?}");
        assert_eq!(genesis_block._block_hash(), genesis_hash);
        let block = client.block(genesis_hash, network.into()).await.unwrap();
        assert_eq!(block._block_hash(), genesis_hash);
        assert_eq!(
            block.transactions_iter().next().unwrap().txid(),
            genesis_txid
        );

        // Genesis transaction cannot be fetched via REST API in Bitcoin networks
        // It's only available embedded within the genesis block
        match network.into() {
            crate::be::Family::Elements => {
                let genesis_tx = client.tx(genesis_txid, network.into()).await.unwrap();
                assert_eq!(genesis_tx.txid(), genesis_txid);
            }
            crate::be::Family::Bitcoin => {
                // Skip genesis transaction fetch for Bitcoin networks
                // The genesis transaction is special and not indexed in Bitcoin Core
                log::debug!("Skipping genesis transaction fetch for Bitcoin network");
            }
        }
        client.mempool(false).await.unwrap();

        if !client.use_esplora {
            match network.into() {
                Family::Bitcoin => {
                    let support_verbose = client.mempool(true).await.is_ok();
                    assert!(support_verbose);
                }
                Family::Elements => {
                    let support_verbose = client.mempool(true).await.is_ok();
                    assert!(!support_verbose);
                }
            }
        }

        if let Some(another_txid) = another_txid {
            let another_txid = crate::be::Txid::from_str(another_txid).unwrap();
            let another_tx = client.tx(another_txid, network.into()).await.unwrap();
            assert_eq!(another_tx.txid(), another_txid);
        }

        let header = client
            .block_header(genesis_hash, network.into())
            .await
            .unwrap();
        assert_eq!(block.header(), header);
        assert_eq!(header.block_hash(), genesis_hash, "network:{network}");

        let header_json = client
            .block_header_json(genesis_hash, network.into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(header_json.hash, genesis_hash);
        match network {
            Network::Bitcoin => {
                let block_1 = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
                assert_eq!(
                    header_json.nextblockhash,
                    Some(BlockHash::from_str(block_1).unwrap())
                );
            }
            Network::BitcoinTestnet4 => {
                let block_1 = "0000000012982b6d5f621229286b880e909984df669c2afabb102ce311b13f28";
                assert_eq!(
                    header_json.nextblockhash,
                    Some(BlockHash::from_str(block_1).unwrap())
                );
            }
            Network::Liquid => {
                let block_1 = "afafbbdfc52a45e51a3b634f391f952f6bdfd14ef74b34925954b4e20d0ad639";
                assert_eq!(
                    header_json.nextblockhash,
                    Some(BlockHash::from_str(block_1).unwrap())
                );
            }
            Network::LiquidTestnet => {
                let block_1 = "f1fedb4e9f09f0e30181432379aa33b60fa044165f951be58614e614b9f884ca";
                assert_eq!(
                    header_json.nextblockhash,
                    Some(BlockHash::from_str(block_1).unwrap())
                );
            }
            _ => {
                assert_eq!(header_json.nextblockhash, None, "network:{network}");
            }
        }

        let fee_estimates = client.fee_estimates().await.unwrap();
        assert!(fee_estimates.values().all(|&f| f > 0.0));
    }
}
