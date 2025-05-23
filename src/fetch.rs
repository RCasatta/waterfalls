use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use anyhow::{anyhow, Context};
use elements::{
    encode::{serialize_hex, Decodable},
    Block, BlockHash, Transaction, Txid,
};
use hyper::body::Buf;
use serde::Deserialize;
use serde_json::json;
use tokio::time::sleep;

use crate::server::{Arguments, Network};

#[derive(Clone)]
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
    pub fn new(args: &Arguments) -> Client {
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
        };
        let use_esplora = args.use_esplora;
        let base_url = if use_esplora {
            esplora_url.clone()
        } else {
            let node_url = args.node_url.clone();
            let port = args.network.default_elements_listen_port();
            node_url.unwrap_or(format!("{LOCAL}:{port}"))
        };
        log::info!("connecting to {base_url}");
        Client {
            client: reqwest::Client::new(),
            use_esplora,
            base_url,
            esplora_url,
            rpc_user_password: args.rpc_user_password.clone(),
        }
    }

    // `curl http://127.0.0.1:7041/rest/blockhashbyheight/0.hex`
    // GET /block-height/:height
    pub async fn block_hash(
        &self,
        height: u32,
    ) -> Result<Option<BlockHash>, Box<dyn std::error::Error + Send + Sync>> {
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
        } else if response.status() == 404 {
            Ok(None)
        } else {
            panic!("{url} return unexpected status {status} for block_hash");
        }
    }

    /// GET /rest/block/<BLOCK-HASH>.<bin|hex|json>
    /// GET /block/:hash/raw
    pub async fn block(
        &self,
        hash: BlockHash,
    ) -> Result<Block, Box<dyn std::error::Error + Send + Sync>> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/block/{hash}/raw")
        } else {
            format!("{base}/rest/block/{hash}.bin",)
        };
        let bytes = self.client.get(&url).send().await?.bytes().await?;

        let block = Block::consensus_decode(bytes.as_ref())?;
        Ok(block)
    }

    // curl http://127.0.0.1:7041/rest/
    // curl -s http://localhost:7041/rest/mempool/contents.json | jq
    // verbose false is not supported on liquid
    pub async fn mempool(&self) -> Result<HashSet<Txid>, Box<dyn std::error::Error + Send + Sync>> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/mempool/txids")
        } else {
            format!("{base}/rest/mempool/contents.json")
        };

        let resp = self.client.get(&url).send().await.with_context(|| {
            format!("failure opening {url}, is it correct and rest flag enabled in the node?")
        })?;
        let body_bytes = resp
            .bytes()
            .await
            .with_context(|| format!("failure reading {url} body in bytes"))?;

        Ok(if self.use_esplora {
            let content: HashSet<Txid> = serde_json::from_reader(body_bytes.reader())
                .with_context(|| format!("failure converting {url} body in HashSet<Txid>"))?;
            content
        } else {
            let content: HashMap<Txid, Empty> = serde_json::from_reader(body_bytes.reader())
                .with_context(|| {
                    format!("failure converting {url} body in HashMap<Txid, Empty> ")
                })?;

            content.into_keys().collect()
        })
    }

    /// GET /rest/tx/<TX-HASH>.<bin|hex|json>
    pub async fn tx(
        &self,
        txid: Txid,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/tx/{txid}/raw")
        } else {
            format!("{base}/rest/tx/{txid}.bin",)
        };

        let bytes = self.client.get(&url).send().await?.bytes().await?;

        let tx = Transaction::consensus_decode(bytes.as_ref())?;
        Ok(tx)
    }

    /// POST /tx
    ///
    /// When using the node it must go through RPC interface because the node doesn't support broadcasting via REST
    /// We can't go full RPC for other methods because RPC doesn't return binary data
    ///
    pub async fn broadcast(&self, tx: &Transaction) -> Result<Txid, anyhow::Error> {
        let tx_hex = serialize_hex(tx);

        let response = if self.use_esplora {
            let url = format!("{}/tx", &self.esplora_url);
            log::info!("broadcasting to {}", url);

            self.client.post(&url).body(tx_hex).send().await?
        } else {
            let rpc_auth = self
                .rpc_user_password
                .as_ref()
                .expect("validated by Arguments");
            let url = self
                .base_url
                .replace("http://", &format!("http://{rpc_auth}@",));
            log::info!("broadcasting to url {url}");

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
            anyhow::bail!("Returning ({status}) not 200, body is {text}");
        }
        let value: serde_json::Value = serde_json::from_str(&text)?;
        let txid_text = value
            .get("result")
            .ok_or(anyhow!("unexpected json without result"))?
            .as_str()
            .ok_or(anyhow!("unexpected non-string result"))?;

        let txid = Txid::from_str(txid_text)?;
        assert_eq!(txid, tx.txid());
        Ok(txid)
    }

    pub(crate) async fn block_or_wait(&self, block_hash: BlockHash) -> Block {
        loop {
            match self.block(block_hash).await {
                Ok(b) => return b,
                Err(e) => {
                    log::warn!("Failing for block({block_hash}) err {e:?}");
                    sleep(std::time::Duration::from_secs(1)).await
                }
            }
        }
    }

    pub(crate) async fn block_hash_or_wait(&self, height: u32) -> BlockHash {
        let mut i = 0;
        loop {
            match self.block_hash(height).await {
                Ok(Some(b)) => {
                    return b;
                }
                Ok(None) => {
                    if i > 100 {
                        // when waiting for a new block, 60 fails are expected
                        log::warn!("waiting for blockhash({height}) for more than 100 secs");
                    }
                }
                Err(e) => {
                    log::warn!("Failing for blockhash({height}) with err {e:?}");
                }
            }
            i += 1;
            sleep(std::time::Duration::from_secs(1)).await
        }
    }

    pub(crate) async fn tx_or_wait(&self, txid: Txid) -> Transaction {
        loop {
            match self.tx(txid).await {
                Ok(t) => return t,
                Err(e) => {
                    log::warn!("Failing for tx({txid}) err {e:?}");
                    sleep(std::time::Duration::from_secs(1)).await
                }
            }
        }
    }
}

#[derive(Deserialize)]
pub struct Empty {}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use elements::{BlockHash, Txid};

    use crate::server::{Arguments, Network};

    use super::Client;

    #[tokio::test]
    #[ignore = "connects to prod server"]
    async fn test_client_esplora() {
        let mut args = Arguments::default();
        args.use_esplora = true;
        for network in [Network::Liquid, Network::LiquidTestnet] {
            args.network = network;
            let client = Client::new(&args);
            test(client, network).await;
        }
    }

    #[tokio::test]
    #[ignore = "connects to local node instance"]
    async fn test_client_local() {
        let mut args = Arguments::default();
        args.use_esplora = false;

        for network in [Network::Liquid, Network::LiquidTestnet] {
            args.network = network;
            let client = Client::new(&args);
            test(client, network).await;
        }
    }

    async fn test(client: Client, network: Network) {
        let (genesis_hash, genesis_txid) = if network == Network::LiquidTestnet {
            (
                "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1",
                "0471d2f856b3fdbc4397af272bee1660b77aaf9a4aeb86fdd96110ce00f2b158",
            )
        } else {
            (
                "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003",
                "45de9fd4cb0f2a63b3afc68d26403f0d3c773d6cf2f42508bd8e7d7704f267d7",
            )
        };

        let genesis_hash = BlockHash::from_str(&genesis_hash).unwrap();
        let genesis_txid = Txid::from_str(&genesis_txid).unwrap();

        let fetched = client.block_hash(0).await.unwrap().unwrap();
        assert_eq!(genesis_hash, fetched, "network:{network}");
        let genesis_block = client.block(genesis_hash).await.unwrap();
        assert_eq!(genesis_block.block_hash(), genesis_hash);
        let genesis_tx = client.tx(genesis_txid).await.unwrap();
        assert_eq!(genesis_tx.txid(), genesis_txid);
        client.mempool().await.unwrap();
    }
}
