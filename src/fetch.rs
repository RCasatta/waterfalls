use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use elements::{encode::Decodable, Block, BlockHash, Transaction, Txid};
use hyper::body::Buf;
use serde::Deserialize;
use tokio::time::sleep;

pub struct Client {
    client: reqwest::Client,
    testnet: bool,
    use_esplora: bool,
}

const BS: &str = "https://blockstream.info";
const LOCAL: &str = "http://127.0.0.1";

impl Client {
    pub fn new(testnet: bool, use_esplora: bool) -> Client {
        Client {
            client: reqwest::Client::new(),
            testnet,
            use_esplora,
        }
    }

    // `curl http://127.0.0.1:7041/rest/blockhashbyheight/0.hex`
    // GET /block-height/:height
    pub async fn block_hash(
        &self,
        height: u32,
    ) -> Result<Option<BlockHash>, Box<dyn std::error::Error + Send + Sync>> {
        let url = match (self.testnet, self.use_esplora) {
            (true, false) => format!("{LOCAL}:7039/rest/blockhashbyheight/{height}.hex"),
            (true, true) => format!("{BS}/liquidtestnet/api/block-height/{height}"),
            (false, false) => format!("{LOCAL}:7041/rest/blockhashbyheight/{height}.hex"),
            (false, true) => format!("{BS}/liquid/api/block-height/{height}"),
        };
        let response = self.client.get(&url).send().await?;
        if response.status() == 200 {
            let hex = response.text().await?;
            Ok(Some(BlockHash::from_str(hex.trim())?))
        } else {
            Ok(None)
        }
    }

    /// GET /rest/block/<BLOCK-HASH>.<bin|hex|json>
    /// GET /block/:hash/raw
    pub async fn block(
        &self,
        hash: BlockHash,
    ) -> Result<Block, Box<dyn std::error::Error + Send + Sync>> {
        let url = match (self.testnet, self.use_esplora) {
            (true, false) => format!("{LOCAL}:7039/rest/block/{hash}.bin"),
            (true, true) => format!("{BS}/liquidtestnet/api/block/{hash}/raw"),
            (false, false) => format!("{LOCAL}:7041/rest/block/{hash}.bin"),
            (false, true) => format!("{BS}/liquid/api/block/{hash}/raw"),
        };
        let bytes = self.client.get(&url).send().await?.bytes().await?;

        let block = Block::consensus_decode(bytes.as_ref())?;
        Ok(block)
    }

    // curl http://127.0.0.1:7041/rest/
    // curl -s http://localhost:7041/rest/mempool/contents.json | jq
    // verbose false is not supported on liquid
    pub async fn mempool(&self) -> Result<HashSet<Txid>, Box<dyn std::error::Error + Send + Sync>> {
        let url = match (self.testnet, self.use_esplora) {
            (true, false) => format!("{LOCAL}:7039/rest/mempool/contents.json"),
            (true, true) => format!("{BS}/liquidtestnet/api/mempool/txids"),
            (false, false) => format!("{LOCAL}:7041/rest/mempool/contents.json"),
            (false, true) => format!("{BS}/liquid/api/mempool/txids"),
        };

        let resp = self.client.get(url).send().await?;
        let body_bytes = resp.bytes().await?;

        Ok(if self.use_esplora {
            let content: HashSet<Txid> = serde_json::from_reader(body_bytes.reader())?;
            content
        } else {
            let content: HashMap<Txid, Empty> = serde_json::from_reader(body_bytes.reader())?;
            content.into_keys().collect()
        })
    }

    /// GET /rest/tx/<TX-HASH>.<bin|hex|json>
    pub async fn tx(
        &self,
        txid: Txid,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        let url = match (self.testnet, self.use_esplora) {
            (true, false) => format!("{LOCAL}:7039/rest/tx/{txid}.bin"),
            (true, true) => format!("{BS}/liquidtestnet/api/tx/{txid}/raw"),
            (false, false) => format!("{LOCAL}:7041/rest/tx/{txid}.bin"),
            (false, true) => format!("{BS}/liquid/api/tx/{txid}/raw"),
        };

        let bytes = self.client.get(&url).send().await?.bytes().await?;

        let tx = Transaction::consensus_decode(bytes.as_ref())?;
        Ok(tx)
    }

    pub(crate) async fn block_or_wait(&self, block_hash: BlockHash) -> Block {
        loop {
            match self.block(block_hash).await {
                Ok(b) => return b,
                Err(e) => {
                    println!("Failing for block({block_hash}) err {e:?}");
                    sleep(std::time::Duration::from_secs(1)).await
                }
            }
        }
    }

    pub(crate) async fn tx_or_wait(&self, txid: Txid) -> Transaction {
        loop {
            match self.tx(txid).await {
                Ok(t) => return t,
                Err(e) => {
                    println!("Failing for tx({txid}) err {e:?}");
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

    use super::Client;

    #[tokio::test]
    #[ignore = "connects to prod server"]
    async fn test_client_esplora() {
        for is_testnet in [true, false] {
            let client = Client::new(is_testnet, true);
            test(client, is_testnet).await;
        }
    }

    #[tokio::test]
    #[ignore = "connects to local node instance"]
    async fn test_client_local() {
        for is_testnet in [true, false] {
            let client = Client::new(is_testnet, false);
            test(client, is_testnet).await;
        }
    }

    async fn test(client: Client, is_testnet: bool) {
        let (genesis_hash, genesis_txid) = if is_testnet {
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
        assert_eq!(genesis_hash, fetched, "is_testnet:{is_testnet}");
        let genesis_block = client.block(genesis_hash).await.unwrap();
        assert_eq!(genesis_block.block_hash(), genesis_hash);
        let genesis_tx = client.tx(genesis_txid).await.unwrap();
        assert_eq!(genesis_tx.txid(), genesis_txid);
        client.mempool().await.unwrap();
    }
}
