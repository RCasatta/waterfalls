use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use anyhow::{anyhow, Context};
use bitcoin::hex::FromHex;
use elements::{encode::Decodable, BlockHash, Txid};
use hyper::body::Buf;
use serde::Deserialize;
use serde_json::json;
use tokio::time::sleep;

use crate::{
    be::{self, Family},
    server::{Arguments, Network},
};

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

            Network::Bitcoin => args.esplora_url.clone().unwrap_or(format!("{BS}/api")),
            Network::BitcoinTestnet => args
                .esplora_url
                .clone()
                .unwrap_or(format!("{BS}/testnet/api")),
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
        } else if response.status() == 404 || response.status() == 503 {
            Ok(None)
        } else {
            log::error!("{url} return unexpected status {status} for block_hash");
            panic!("{url} return unexpected status {status} for block_hash");
        }
    }

    /// GET /rest/block/<BLOCK-HASH>.<bin|hex|json>
    /// GET /block/:hash/raw
    pub async fn block(
        &self,
        hash: BlockHash,
        family: Family,
    ) -> Result<be::Block, Box<dyn std::error::Error + Send + Sync>> {
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
            return Err(format!("{url} return not found.").into());
        } else if status != 200 {
            return Err(format!("{url} return unexpected status {status}").into());
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

    /// GET /rest/headers/<BLOCK-HASH>.<bin|hex|json>
    /// GET /block/:hash/header
    pub async fn block_header(
        &self,
        hash: BlockHash,
        family: Family,
    ) -> Result<be::BlockHeader, Box<dyn std::error::Error + Send + Sync>> {
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
        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if status == 404 {
            return Err(format!("{url} return not found.").into());
        } else if status != 200 {
            return Err(format!("{url} return unexpected status {status}").into());
        }

        match family {
            Family::Bitcoin => {
                let bytes = if self.use_esplora {
                    let text = resp.text().await?;
                    Vec::<u8>::from_hex(&text)
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
                    Vec::<u8>::from_hex(&text)
                        .map_err(|_| anyhow!("failing converting {text} to bytes"))?
                } else {
                    resp.bytes().await?.to_vec()
                };
                let header = elements::BlockHeader::consensus_decode(&bytes[..])?;
                Ok(be::BlockHeader::Elements(Box::new(header)))
            }
        }
    }

    // curl http://127.0.0.1:7041/rest/
    // curl -s http://localhost:7041/rest/mempool/contents.json | jq
    // verbose false is not supported on liquid
    pub async fn mempool(
        &self,
        support_verbose: bool,
    ) -> Result<HashSet<Txid>, Box<dyn std::error::Error + Send + Sync>> {
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
            let content: HashSet<Txid> = serde_json::from_reader(body_bytes.reader())
                .with_context(|| format!("failure converting {url} body in HashSet<Txid>"))?;
            content
        } else {
            if support_verbose {
                serde_json::from_reader(body_bytes.reader())
                    .with_context(|| format!("failure converting {url} body in HashSet<Txid> "))?
            } else {
                let content: HashMap<Txid, Empty> = serde_json::from_reader(body_bytes.reader())
                    .with_context(|| {
                        format!("failure converting {url} body in HashMap<Txid, Empty> ")
                    })?;

                content.into_keys().collect()
            }
        })
    }

    /// GET /rest/tx/<TX-HASH>.<bin|hex|json>
    pub async fn tx(
        &self,
        txid: Txid,
        family: Family,
    ) -> Result<be::Transaction, Box<dyn std::error::Error + Send + Sync>> {
        let base = &self.base_url;
        let url = if self.use_esplora {
            format!("{base}/tx/{txid}/raw")
        } else {
            format!("{base}/rest/tx/{txid}.bin",)
        };
        let resp = self.client.get(&url).send().await?;

        let status = resp.status();
        if status == 404 {
            return Err(format!("Transaction {txid} not found").into());
        } else if status != 200 {
            return Err(format!("Request failed with status {status}").into());
        }

        let bytes = resp.bytes().await?;

        match family {
            Family::Bitcoin => {
                let tx = <bitcoin::Transaction as bitcoin::consensus::Decodable>::consensus_decode(
                    &mut bytes.as_ref(),
                )?;
                Ok(be::Transaction::Bitcoin(tx))
            }
            Family::Elements => {
                let tx = elements::Transaction::consensus_decode(bytes.as_ref())?;
                Ok(be::Transaction::Elements(tx))
            }
        }
    }

    /// POST /tx
    ///
    /// When using the node it must go through RPC interface because the node doesn't support broadcasting via REST
    /// We can't go full RPC for other methods because RPC doesn't return binary data
    ///
    pub async fn broadcast(&self, tx: &be::Transaction) -> Result<Txid, anyhow::Error> {
        let tx_hex = tx.serialize_hex();

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

    pub(crate) async fn block_or_wait(&self, block_hash: BlockHash, family: Family) -> be::Block {
        loop {
            match self.block(block_hash, family).await {
                Ok(b) => return b,
                Err(e) => {
                    log::warn!("Failing for block({block_hash}) err {e:?} family:{family:?}");
                    sleep(std::time::Duration::from_secs(1)).await
                }
            }
        }
    }

    pub(crate) async fn block_hash_or_wait(&self, height: u32) -> BlockHash {
        let mut i = 1;
        loop {
            match self.block_hash(height).await {
                Ok(Some(b)) => {
                    return b;
                }
                Ok(None) => {
                    if i % 100 == 0 {
                        // when waiting for a new block, 60 fails are expected
                        log::warn!("waiting for blockhash({height}) for more than {i} secs");
                        // TODO this doesn't make sense for bitcoin
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

    pub(crate) async fn tx_or_wait(&self, txid: Txid, family: Family) -> be::Transaction {
        loop {
            match self.tx(txid, family).await {
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

    use crate::{
        server::{Arguments, Network},
        test_env, Family,
    };

    use super::Client;

    #[tokio::test]
    #[ignore = "connects to prod server"]
    async fn test_client_esplora() {
        let _ = env_logger::try_init();
        let mut args = Arguments::default();
        args.use_esplora = true;
        for network in [Network::Bitcoin, Network::Liquid, Network::LiquidTestnet] {
            args.network = network;
            let client = Client::new(&args);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            test(client, network).await;
        }
    }

    #[tokio::test]
    #[ignore = "connects to local node instance"]
    async fn test_client_local_regtest_elements() {
        let elementsd = test_env::launch_elements(
            std::env::var("ELEMENTSD_EXEC").expect("ELEMENTSD_EXEC must be set"),
        );
        let mut args = Arguments::default();
        args.use_esplora = false;
        args.network = Network::ElementsRegtest;
        args.node_url = Some(elementsd.rpc_url());
        let client = Client::new(&args);
        test(client, args.network).await;
    }

    #[tokio::test]
    #[ignore = "connects to local node instance"]
    async fn test_client_local_liquid() {
        let client = init_client(Network::Liquid);
        test(client, Network::Liquid).await;
    }

    #[tokio::test]
    #[ignore = "connects to local node instance"]
    async fn test_client_local_liquid_testnet() {
        let client = init_client(Network::LiquidTestnet);
        test(client, Network::LiquidTestnet).await;
    }

    #[tokio::test]
    #[ignore = "connects to local node instance"]
    async fn test_client_local_bitcoin() {
        let client = init_client(Network::Bitcoin);
        test(client, Network::Bitcoin).await;
    }

    fn init_client(network: Network) -> Client {
        let mut args = Arguments::default();
        args.use_esplora = false;
        args.network = network;
        Client::new(&args)
    }

    #[tokio::test]
    #[ignore = "connects to local node instance"]
    async fn test_client_local_regtest_bitcoin() {
        let _ = env_logger::try_init();
        let bitcoind = test_env::launch_bitcoin(
            std::env::var("BITCOIND_EXEC").expect("BITCOIND_EXEC must be set"),
        );
        let mut args = Arguments::default();
        args.use_esplora = false;
        args.network = Network::BitcoinRegtest;
        args.node_url = Some(bitcoind.rpc_url());
        let client = Client::new(&args);
        test(client, args.network).await;
    }

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
            Network::BitcoinRegtest => (
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                None,
            ),
            Network::BitcoinSignet => todo!(),
        };

        let genesis_hash = BlockHash::from_str(&genesis_hash).unwrap();
        let genesis_txid = Txid::from_str(&genesis_txid).unwrap();

        let fetched = client.block_hash(0).await.unwrap().unwrap();
        assert_eq!(genesis_hash, fetched, "network:{network}");
        let genesis_block = client.block(genesis_hash, network.into()).await.unwrap();
        log::debug!("genesis_block: {genesis_block:?}");
        assert_eq!(genesis_block.block_hash(), genesis_hash);
        let block = client.block(genesis_hash, network.into()).await.unwrap();
        assert_eq!(block.block_hash(), genesis_hash);
        assert_eq!(block.transactions()[0].txid(), genesis_txid);

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

        println!("mempool true returns: {:?}", client.mempool(false).await);

        println!("mempool true returns: {:?}", client.mempool(true).await);

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
            let another_txid = Txid::from_str(another_txid).unwrap();
            let another_tx = client.tx(another_txid, network.into()).await.unwrap();
            assert_eq!(another_tx.txid(), another_txid);
        }

        let header = client
            .block_header(genesis_hash, network.into())
            .await
            .unwrap();
        assert_eq!(block.header(), header);
        assert_eq!(header.block_hash(), genesis_hash, "network:{network}");
    }
}
