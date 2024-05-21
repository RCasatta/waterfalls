use std::{collections::HashMap, path::Path, sync::Arc};

use elements::{BlockHash, OutPoint};
use tokio::sync::Mutex;

use crate::{db::DBStore, Height};

type ScriptHash = u64;

/// Shared state across the service
#[derive(Debug)]
pub(crate) struct State {
    /// The 0th element contain the genesis block hash, and so on.
    headers: Mutex<Vec<BlockHash>>,

    pub tip_height: Height,

    pub db: Arc<DBStore>,
}

impl State {
    pub fn new(genesis: BlockHash, path: &Path, tip_height: Height) -> State {
        State {
            headers: Mutex::new(vec![genesis]),
            db: Arc::new(DBStore::open(path).unwrap()),
            tip_height,
        }
    }
}
