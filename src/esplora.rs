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

/// GET /block/:hash/raw
pub async fn block(hash: BlockHash) -> Result<Block, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://blockstream.info/liquid/api/block/{hash}/raw");
    let bytes = reqwest::get(&url).await?.bytes().await?;

    let block = Block::consensus_decode(bytes.as_ref())?;
    Ok(block)
}

/// GET /block-height/:height
pub async fn block_hash(
    height: u32,
) -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://blockstream.info/liquid/api/block-height/{height}");
    println!("{url}");
    let hex = reqwest::get(&url).await?.text().await?;

    Ok(BlockHash::from_str(&hex)?)
}
