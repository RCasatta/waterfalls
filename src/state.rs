use tokio::sync::Mutex;

use crate::{db::DBStore, mempool::Mempool};

pub(crate) struct State {
    pub(crate) db: DBStore,
    pub(crate) mempool: Mutex<Mempool>,
    // pub(crate) block_hashes: Mutex<Vec<BlockHash>>,
}
