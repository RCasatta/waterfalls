use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use elements::{encode::Decodable, Block, BlockHash, Transaction, Txid};
use hyper::body::Buf;
use serde::Deserialize;

// use crate::Height;

// pub async fn tip_hash() -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
//     let body = reqwest::get("https://blockstream.info/liquid/api/blocks/tip/hash")
//         .await?
//         .text()
//         .await?;
//     Ok(BlockHash::from_str(&body)?)
// }

// pub async fn tip_height() -> Result<Height, Box<dyn std::error::Error + Send + Sync>> {
//     let body = reqwest::get("https://blockstream.info/liquid/api/blocks/tip/height")
//         .await?
//         .text()
//         .await?;
//     Ok(Height::from_str(&body)?)
// }

pub struct Client {
    client: reqwest::Client,
}

impl Client {
    pub fn new() -> Client {
        Client {
            client: reqwest::Client::new(),
        }
    }

    //curl http://127.0.0.1:7041/rest/blockhashbyheight/0.hex
    /// GET /block-height/:height
    pub async fn block_hash(
        &self,
        height: u32,
    ) -> Result<Option<BlockHash>, Box<dyn std::error::Error + Send + Sync>> {
        //let url = format!("https://blockstream.info/liquid/api/block-height/{height}");
        let url = format!("http://127.0.0.1:7041/rest/blockhashbyheight/{height}.hex");
        // println!("{url}");
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
        // let url = format!("https://blockstream.info/liquid/api/block/{hash}/raw");
        let url = format!("http://127.0.0.1:7041/rest/block/{hash}.bin");
        // println!("{url}");

        let bytes = self.client.get(&url).send().await?.bytes().await?;

        let block = Block::consensus_decode(bytes.as_ref())?;
        Ok(block)
    }

    // curl http://127.0.0.1:7041/rest/
    // curl -s http://localhost:7041/rest/mempool/contents.json | jq
    // verbose false is not supported on liquid
    pub async fn mempool(&self) -> Result<HashSet<Txid>, Box<dyn std::error::Error + Send + Sync>> {
        let uri = "http://127.0.0.1:7041/rest/mempool/contents.json";
        let resp = self.client.get(uri).send().await?;
        let body_bytes = resp.bytes().await?;

        let content: HashMap<Txid, Empty> = serde_json::from_reader(body_bytes.reader())?;

        Ok(content.into_keys().collect())
    }

    /// GET /rest/tx/<TX-HASH>.<bin|hex|json>
    pub async fn tx(
        &self,
        hash: Txid,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        // let url = format!("https://blockstream.info/liquid/api/block/{hash}/raw");
        let url = format!("http://127.0.0.1:7041/rest/tx/{hash}.bin");

        let bytes = self.client.get(&url).send().await?.bytes().await?;

        let tx = Transaction::consensus_decode(bytes.as_ref())?;
        Ok(tx)
    }
}

#[derive(Deserialize)]
pub struct Empty {}
