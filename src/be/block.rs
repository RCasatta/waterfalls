use bitcoin::hashes::Hash;

use crate::be;

#[derive(Debug, Clone)]
pub enum Block {
    Bitcoin(Box<bitcoin::Block>),
    Elements(Box<elements::Block>),
}

pub(crate) fn elements_block_hash(hash: bitcoin::BlockHash) -> elements::BlockHash {
    elements::BlockHash::from_slice(hash.as_ref()).expect("every 32 bytes is a valid block hash")
}

impl Block {
    pub fn header(&self) -> be::BlockHeader {
        match self {
            Block::Bitcoin(block) => be::BlockHeader::Bitcoin(Box::new(block.header)),
            Block::Elements(block) => be::BlockHeader::Elements(Box::new(block.header.clone())),
        }
    }

    pub(crate) fn _block_hash(&self) -> elements::BlockHash {
        match self {
            Block::Bitcoin(block) => elements_block_hash(block.block_hash()),
            Block::Elements(block) => block.block_hash(),
        }
    }

    pub(crate) fn _time(&self) -> u32 {
        match self {
            Block::Bitcoin(block) => block.header.time,
            Block::Elements(block) => block.header.time,
        }
    }

    /// Iterator over transactions without cloning - more efficient for indexing
    pub(crate) fn transactions_iter(&self) -> impl Iterator<Item = be::TransactionRef> {
        match self {
            Block::Bitcoin(block) => TransactionIterator::Bitcoin(block.txdata.iter()),
            Block::Elements(block) => TransactionIterator::Elements(block.txdata.iter()),
        }
    }
}

pub(crate) enum TransactionIterator<'a> {
    Bitcoin(std::slice::Iter<'a, bitcoin::Transaction>),
    Elements(std::slice::Iter<'a, elements::Transaction>),
}

impl<'a> Iterator for TransactionIterator<'a> {
    type Item = be::TransactionRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            TransactionIterator::Bitcoin(iter) => iter.next().map(be::TransactionRef::Bitcoin),
            TransactionIterator::Elements(iter) => iter.next().map(be::TransactionRef::Elements),
        }
    }
}
