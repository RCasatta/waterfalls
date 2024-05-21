use std::{collections::HashMap, path::Path, sync::Arc};

use elements::{BlockHash, OutPoint};
use tokio::sync::Mutex;

use crate::db::DBStore;

type ScriptHash = u64;

/// Shared state across the service
#[derive(Debug)]
pub(crate) struct State {
    /// 8 random bytes used to salt hashes to avoid attackers forged collisions
    salt: [u8; 8],

    /// The 0th element contain the genesis block hash, and so on.
    headers: Mutex<Vec<BlockHash>>,

    db: Arc<DBStore>,
}

impl State {
    pub fn new(genesis: BlockHash, path: &Path) -> State {
        State {
            salt: [0u8; 8], // TODO random
            headers: Mutex::new(vec![genesis]),
            db: Arc::new(DBStore::open(path).unwrap()),
        }
    }
}
