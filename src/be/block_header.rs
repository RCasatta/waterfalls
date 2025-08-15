use crate::be::block::elements_block_hash;
use crate::{be, Family};
use elements::hex::FromHex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockHeader {
    Bitcoin(Box<bitcoin::block::Header>),
    Elements(Box<elements::BlockHeader>),
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
            BlockHeader::Bitcoin(header) => {
                bitcoin::consensus::encode::serialize_hex(header.as_ref())
            }
            BlockHeader::Elements(header) => elements::encode::serialize_hex(header.as_ref()),
        }
    }

    pub(crate) fn time(&self) -> u32 {
        match self {
            BlockHeader::Bitcoin(header) => header.time,
            BlockHeader::Elements(header) => header.time,
        }
    }

    pub fn prev_blockhash(&self) -> elements::BlockHash {
        match self {
            BlockHeader::Bitcoin(header) => elements_block_hash(header.prev_blockhash),
            BlockHeader::Elements(header) => header.prev_blockhash,
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8], family: be::Family) -> Result<Self, anyhow::Error> {
        Ok(match family {
            Family::Bitcoin => {
                let bitcoin_header =
                    <bitcoin::block::Header as bitcoin::consensus::Decodable>::consensus_decode(
                        &mut &bytes[..],
                    )?;
                be::BlockHeader::Bitcoin(Box::new(bitcoin_header))
            }
            Family::Elements => {
                let elements_header =
                    <elements::BlockHeader as elements::encode::Decodable>::consensus_decode(
                        bytes,
                    )?;
                be::BlockHeader::Elements(Box::new(elements_header))
            }
        })
    }

    pub(crate) fn from_str(header_hex: &str, family: be::Family) -> Result<Self, anyhow::Error> {
        let bytes = Vec::<u8>::from_hex(header_hex).unwrap();
        Self::from_bytes(&bytes, family)
    }
}
