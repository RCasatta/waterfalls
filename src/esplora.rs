use std::str::FromStr;

use elements::{encode::Decodable, Block, BlockHash};

pub async fn tip() -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
    let body = reqwest::get("https://blockstream.info/liquid/api/blocks/tip/hash")
        .await?
        .text()
        .await?;
    Ok(BlockHash::from_str(&body)?)
}

/// GET /block/:hash/raw
pub async fn block(hash: BlockHash) -> Result<Block, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://blockstream.info/liquid/api//block/{hash}/raw");
    println!("{url}");
    let bytes = reqwest::get(&url).await?.bytes().await?;

    let block = Block::consensus_decode(bytes.as_ref())?;
    Ok(block)
}
