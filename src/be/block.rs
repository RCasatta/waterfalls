use bitcoin::hashes::Hash;

pub enum Block {
    Bitcoin(bitcoin::Block),
    Elements(elements::Block),
}

impl Block {
    pub fn header_hex(&self) -> String {
        match self {
            Block::Bitcoin(block) => bitcoin::consensus::encode::serialize_hex(&block.header),
            Block::Elements(block) => elements::encode::serialize_hex(&block.header),
        }
    }

    pub(crate) fn _block_hash(&self) -> elements::BlockHash {
        match self {
            Block::Bitcoin(block) => {
                let hash = block.block_hash();
                elements::BlockHash::from_slice(hash.as_ref())
                    .expect("every 32 bytes is a valid block hash")
            }
            Block::Elements(block) => block.block_hash(),
        }
    }

    pub(crate) fn time(&self) -> u32 {
        match self {
            Block::Bitcoin(block) => block.header.time,
            Block::Elements(block) => block.header.time,
        }
    }
}
