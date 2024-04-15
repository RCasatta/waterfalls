use std::collections::HashMap;

use elements::{BlockHash, OutPoint};
use tokio::sync::Mutex;

type ScriptHash = u64;

/// Shared state across the service
#[derive(Debug)]
pub(crate) struct State {
    /// 8 random bytes used to salt hashes to avoid attackers forged collisions
    salt: [u8; 8],

    /// The 0th element contain the genesis block hash, and so on.
    headers: Mutex<Vec<BlockHash>>,

    /// The key is an hash of a script pubkey
    /// The value is the height of blocks in which the script pubkey is present
    /// May contain false positives
    scripts: Mutex<HashMap<ScriptHash, Vec<u32>>>,

    /// The unspent transaction output set
    utxo: Mutex<HashMap<OutPoint, ScriptHash>>,
}

impl State {
    pub fn new(genesis: BlockHash) -> State {
        State {
            salt: [0u8; 8], // TODO random
            headers: Mutex::new(vec![genesis]),
            scripts: Mutex::new(HashMap::new()),
            utxo: Mutex::new(HashMap::new()),
        }
    }
}
