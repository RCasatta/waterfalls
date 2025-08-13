use std::cmp::Ordering;

use crate::{
    server::{derivation_cache::DerivationCache, Mempool},
    store::{AnyStore, BlockMeta},
    Timestamp,
};
use age::x25519::Identity;
use bitcoin::{key::Secp256k1, secp256k1::All, PrivateKey};
use elements::BlockHash;
use tokio::sync::Mutex;

use super::{sign::p2pkh, Error};

pub struct State {
    /// An asymmetric encryption key, the public key is used to optionally encrypt the descriptor field so that it's harder to leak it.
    pub key: Identity,

    /// The private key of the server address used to sign responses
    pub wif_key: PrivateKey,

    pub store: AnyStore,
    pub mempool: Mutex<Mempool>,
    pub blocks_hash_ts: Mutex<Vec<(BlockHash, Timestamp)>>, // TODO should be moved into the Store, but in memory for db

    pub secp: Secp256k1<All>,

    pub max_addresses: usize,

    pub derivation_cache: Mutex<DerivationCache>,
}

impl State {
    pub fn new(
        store: AnyStore,
        key: Identity,
        wif_key: PrivateKey,
        max_addresses: usize,
        derivation_cache_capacity: usize,
    ) -> Result<Self, Error> {
        Ok(State {
            key,
            wif_key,
            store,
            mempool: Mutex::new(Mempool::new()),
            blocks_hash_ts: Mutex::new(Vec::new()),
            secp: bitcoin::key::Secp256k1::new(),
            max_addresses,
            derivation_cache: Mutex::new(DerivationCache::new(derivation_cache_capacity)),
        })
    }

    /// The tip of the blockchain, in other words the block with highest height
    /// It must be granted if returned tip is `Some(x)`, `self.block_hash_ts.get(x)` is some.
    pub async fn tip(&self) -> Option<u32> {
        (self.blocks_hash_ts.lock().await.len() as u32).checked_sub(1)
    }

    pub async fn tip_hash(&self) -> Option<BlockHash> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        blocks_hash_ts.last().map(|e| e.0)
    }

    pub async fn tip_timestamp(&self) -> Option<Timestamp> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        blocks_hash_ts.last().map(|e| e.1)
    }

    pub async fn block_hash(&self, height: u32) -> Option<BlockHash> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        blocks_hash_ts.get(height as usize).map(|e| e.0)
    }
    pub async fn set_hash_ts(&self, meta: &BlockMeta) {
        let mut blocks_hash_ts = self.blocks_hash_ts.lock().await;
        update_hash_ts(&mut *blocks_hash_ts, meta);
    }
    pub fn address(&self) -> bitcoin::Address {
        p2pkh(&self.secp, &self.wif_key)
    }
}

fn update_hash_ts(blocks_hash_ts: &mut Vec<(BlockHash, u32)>, meta: &BlockMeta) {
    match blocks_hash_ts.len().cmp(&(meta.height() as usize)) {
        Ordering::Less => {
            error_panic!(
                "unexpected: height:{} blocks_hash_ts:{}",
                meta.height(),
                blocks_hash_ts.len()
            );
        }
        Ordering::Equal => {
            // Most common case of adding a new block
            blocks_hash_ts.push((meta.hash(), meta.timestamp()))
        }
        Ordering::Greater => {
            // We are reorging
            blocks_hash_ts.get_mut(meta.height() as usize).map(|e| {
                e.0 = meta.hash();
                e.1 = meta.timestamp();
            });
            blocks_hash_ts.truncate(meta.height() as usize + 1); // if the reorg is longer than one block, we need to truncate the vector
        }
    }

    assert_eq!(blocks_hash_ts.len() as u32 - 1, meta.height());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_update_vec() {
        let mut blocks_hash_ts = vec![(
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            0,
        )];

        // Test adding a new block (height 1)
        let meta = BlockMeta::new(
            1,
            BlockHash::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
            100,
        );
        update_hash_ts(&mut blocks_hash_ts, &meta);
        assert_eq!(blocks_hash_ts.len(), 2);
        assert_eq!(blocks_hash_ts[1].0, meta.hash());
        assert_eq!(blocks_hash_ts[1].1, meta.timestamp());

        // Test reorg a block (height 1)
        let meta2 = BlockMeta::new(
            1,
            BlockHash::from_str("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap(),
            101,
        );
        update_hash_ts(&mut blocks_hash_ts, &meta2);
        assert_eq!(blocks_hash_ts.len(), 2);
        assert_eq!(blocks_hash_ts[1].0, meta2.hash());
        assert_eq!(blocks_hash_ts[1].1, meta2.timestamp());

        // Test adding a new block (height 2)
        let meta3 = BlockMeta::new(
            2,
            BlockHash::from_str("3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap(),
            102,
        );
        update_hash_ts(&mut blocks_hash_ts, &meta3);
        assert_eq!(blocks_hash_ts.len(), 3);
        assert_eq!(blocks_hash_ts[2].0, meta3.hash());
        assert_eq!(blocks_hash_ts[2].1, meta3.timestamp());

        // Test double reorg a block (height 1)
        let meta2 = BlockMeta::new(
            1,
            BlockHash::from_str("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap(),
            101,
        );
        update_hash_ts(&mut blocks_hash_ts, &meta2);
        assert_eq!(blocks_hash_ts.len(), 2);
        assert_eq!(blocks_hash_ts[1].0, meta2.hash());
        assert_eq!(blocks_hash_ts[1].1, meta2.timestamp());
    }
}
