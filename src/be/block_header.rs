use crate::be::block::elements_block_hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockHeader {
    Bitcoin(bitcoin::block::Header),
    Elements(elements::BlockHeader),
}

impl BlockHeader {
    pub fn block_hash(&self) -> elements::BlockHash {
        match self {
            BlockHeader::Bitcoin(header) => elements_block_hash(header.block_hash()),
            BlockHeader::Elements(header) => header.block_hash(),
        }
    }

    pub(crate) fn serialize_hex(&self) -> String {
        match self {
            BlockHeader::Bitcoin(header) => bitcoin::consensus::encode::serialize_hex(header),
            BlockHeader::Elements(header) => elements::encode::serialize_hex(header),
        }
    }
}
