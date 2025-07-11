use crate::{Height, ScriptHash, Timestamp, TxSeen};
use anyhow::Result;
use elements::{BlockHash, OutPoint, Script, Txid};
use std::collections::HashMap;

#[cfg(feature = "db")]
pub mod db;

pub mod memory;

pub enum AnyStore {
    #[cfg(feature = "db")]
    Db(db::DBStore),
    Mem(memory::MemoryStore),
}

pub trait Store {
    /// Hash the given script
    ///
    /// It's in the trait cause it can be salted with some random values contained in the
    /// concrete implementation to avoid attacker brute force collisions
    fn hash(&self, script: &Script) -> ScriptHash;

    /// Iterate over blocks metadata to preload those in memory
    fn iter_hash_ts(&self) -> Box<dyn Iterator<Item = BlockMeta> + '_>;

    /// Get given outpoints from the UTXO set to compute the mempool history
    fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<ScriptHash>>>;

    /// Get history of multiple (usually 20 like the gap limit) scripts hash at once
    fn get_history(&self, scripts: &[ScriptHash]) -> Result<Vec<Vec<TxSeen>>>;

    /// update the store with all the data from the last block
    fn update(
        &self,
        block_meta: &BlockMeta,
        utxo_spent: Vec<(u32, OutPoint, Txid)>,
        history_map: HashMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: HashMap<OutPoint, ScriptHash>,
    ) -> Result<()>;
}

impl Store for AnyStore {
    fn hash(&self, script: &Script) -> ScriptHash {
        match self {
            #[cfg(feature = "db")]
            AnyStore::Db(d) => d.hash(script),
            AnyStore::Mem(m) => m.hash(script),
        }
    }

    fn iter_hash_ts(&self) -> Box<dyn Iterator<Item = BlockMeta> + '_> {
        match self {
            #[cfg(feature = "db")]
            AnyStore::Db(d) => d.iter_hash_ts(),
            AnyStore::Mem(m) => m.iter_hash_ts(),
        }
    }

    fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<ScriptHash>>> {
        match self {
            #[cfg(feature = "db")]
            AnyStore::Db(d) => d.get_utxos(outpoints),
            AnyStore::Mem(m) => m.get_utxos(outpoints),
        }
    }

    fn get_history(&self, scripts: &[ScriptHash]) -> Result<Vec<Vec<TxSeen>>> {
        match self {
            #[cfg(feature = "db")]
            AnyStore::Db(d) => d.get_history(scripts),
            AnyStore::Mem(m) => m.get_history(scripts),
        }
    }

    fn update(
        &self,
        block_meta: &BlockMeta,
        utxo_spent: Vec<(u32, OutPoint, Txid)>,
        history_map: HashMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: HashMap<OutPoint, ScriptHash>,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "db")]
            AnyStore::Db(d) => d.update(block_meta, utxo_spent, history_map, utxo_created),
            AnyStore::Mem(m) => m.update(block_meta, utxo_spent, history_map, utxo_created),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockMeta {
    height: Height,
    hash: BlockHash,
    timestamp: Timestamp,
}

impl BlockMeta {
    pub fn new(height: Height, hash: BlockHash, timestamp: Timestamp) -> BlockMeta {
        BlockMeta {
            height,
            hash,
            timestamp,
        }
    }

    pub(crate) fn height(&self) -> Height {
        self.height
    }

    pub(crate) fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub(crate) fn hash(&self) -> BlockHash {
        self.hash
    }
}
