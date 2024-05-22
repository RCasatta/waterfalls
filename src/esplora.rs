use std::str::FromStr;

use elements::{encode::Decodable, Block, BlockHash};

use crate::Height;

pub async fn tip_hash() -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
    let body = reqwest::get("https://blockstream.info/liquid/api/blocks/tip/hash")
        .await?
        .text()
        .await?;
    Ok(BlockHash::from_str(&body)?)
}

pub async fn tip_height() -> Result<Height, Box<dyn std::error::Error + Send + Sync>> {
    let body = reqwest::get("https://blockstream.info/liquid/api/blocks/tip/height")
        .await?
        .text()
        .await?;
    Ok(Height::from_str(&body)?)
}

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
    ) -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
        //let url = format!("https://blockstream.info/liquid/api/block-height/{height}");
        let url = format!("http://127.0.0.1:7041/rest/blockhashbyheight/{height}.hex");
        // println!("{url}");
        let hex = self.client.get(&url).send().await?.text().await?;

        Ok(BlockHash::from_str(hex.trim())?)
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
}
