use crate::{
    server::Mempool,
    store::{AnyStore, BlockMeta},
    Timestamp,
};
use age::x25519::Identity;
use elements::BlockHash;
use tokio::sync::Mutex;

use super::Error;

pub struct State {
    /// An asymmetric encryption key, the public key is used to optionally encrypt the descriptor field so that it's harder to leak it.
    pub key: Identity,

    pub store: AnyStore,
    pub mempool: Mutex<Mempool>,
    pub blocks_hash_ts: Mutex<Vec<(BlockHash, Timestamp)>>, // TODO should be moved into the Store, but in memory for db
}

impl State {
    pub fn new(store: AnyStore, key: Identity) -> Result<Self, Error> {
        Ok(State {
            key,
            store,
            mempool: Mutex::new(Mempool::new()),
            blocks_hash_ts: Mutex::new(Vec::new()),
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
        {
            let mut blocks_hash_ts = self.blocks_hash_ts.lock().await;
            blocks_hash_ts.push((meta.hash(), meta.timestamp()));
            assert_eq!(blocks_hash_ts.len() as u32 - 1, meta.height())
        }
    }
}
