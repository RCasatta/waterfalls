use bitcoin::hashes::Hash;

use crate::be;

#[derive(Debug, Clone)]
pub enum Block {
    Bitcoin(bitcoin::Block),
    Elements(elements::Block),
}

pub(crate) fn elements_block_hash(hash: bitcoin::BlockHash) -> elements::BlockHash {
    elements::BlockHash::from_slice(hash.as_ref()).expect("every 32 bytes is a valid block hash")
}

impl Block {
    pub fn header(&self) -> be::BlockHeader {
        match self {
            Block::Bitcoin(block) => be::BlockHeader::Bitcoin(block.header.clone()),
            Block::Elements(block) => be::BlockHeader::Elements(block.header.clone()),
        }
    }

    pub(crate) fn block_hash(&self) -> elements::BlockHash {
        match self {
            Block::Bitcoin(block) => elements_block_hash(block.block_hash()),
            Block::Elements(block) => block.block_hash(),
        }
    }

    pub(crate) fn time(&self) -> u32 {
        match self {
            Block::Bitcoin(block) => block.header.time,
            Block::Elements(block) => block.header.time,
        }
    }

    pub(crate) fn transactions(&self) -> Vec<be::Transaction> {
        match self {
            Block::Bitcoin(block) => block
                .txdata
                .iter()
                .cloned()
                .map(|tx| be::Transaction::Bitcoin(tx))
                .collect(),
            Block::Elements(block) => block
                .txdata
                .iter()
                .cloned()
                .map(|tx| be::Transaction::Elements(tx))
                .collect(),
        }
    }
}
