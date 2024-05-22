use std::{path::Path, sync::Arc};

use elements::{hashes::Hash, BlockHash};
use tokio::{sync::Mutex, time::sleep};

use crate::{db::DBStore, Height};

/// Shared state across the service
#[derive(Debug)]
pub(crate) struct State {
    /// The 0th element contain the genesis block hash, and so on.
    pub headers: Mutex<Vec<BlockHash>>,

    pub tip_height: Height,

    pub db: Arc<DBStore>,
}

impl State {
    pub fn new(_genesis: BlockHash, path: &Path, tip_height: Height) -> State {
        State {
            headers: Mutex::new(vec![BlockHash::all_zeros(); tip_height as usize]),
            db: Arc::new(DBStore::open(path).unwrap()),
            tip_height,
        }
    }

    pub async fn hash_from_height(&self, height: u32) -> Option<BlockHash> {
        loop {
            let hash = self.headers.lock().await.get(height as usize).cloned();
            if Some(BlockHash::all_zeros()) == hash {
                sleep(std::time::Duration::from_secs(1)).await;
            } else {
                return hash;
            }
        }
    }
}
