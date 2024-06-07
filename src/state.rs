use crate::{db::DBStore, mempool::Mempool, store::BlockMeta, Timestamp};
use elements::BlockHash;
use tokio::sync::Mutex;

pub(crate) struct State {
    pub(crate) db: DBStore,
    pub(crate) mempool: Mutex<Mempool>,
    pub(crate) blocks_hash_ts: Mutex<Vec<(BlockHash, Timestamp)>>,
}

impl State {
    /// The tip of the blockchain, in other words the block with highest height
    /// It must be granted if returned tip is `Some(x)`, `self.block_hash_ts.get(x)` is some.
    pub(crate) async fn tip(&self) -> Option<u32> {
        (self.blocks_hash_ts.lock().await.len() as u32).checked_sub(1)
    }

    pub(crate) async fn tip_hash(&self) -> Option<BlockHash> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        blocks_hash_ts.last().map(|e| e.0)
    }

    pub(crate) async fn block_hash(&self, height: u32) -> Option<BlockHash> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        blocks_hash_ts.get(height as usize).map(|e| e.0)
    }
    pub(crate) async fn set_hash_ts(&self, meta: &BlockMeta) {
        {
            let mut blocks_hash_ts = self.blocks_hash_ts.lock().await;
            blocks_hash_ts.push((meta.hash(), meta.timestamp()));
            assert_eq!(blocks_hash_ts.len() as u32 - 1, meta.height())
        }
    }
}
