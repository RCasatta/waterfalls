use crate::{Height, ScriptHash, Timestamp, TxSeen};
use anyhow::Result;
use elements::{BlockHash, OutPoint, Txid};
use std::collections::BTreeMap;

#[cfg(feature = "db")]
pub mod db;

pub mod memory;

pub enum AnyStore {
    #[cfg(feature = "db")]
    Db(db::DBStore),
    Mem(memory::MemoryStore),
}
impl AnyStore {
    pub(crate) fn stats(&self) -> Option<String> {
        match self {
            AnyStore::Db(dbstore) => dbstore.stats(),
            AnyStore::Mem(_) => None,
        }
    }
}

pub trait Store {
    /// Hash the given script
    ///
    /// It's in the trait cause it can be salted with some random values contained in the
    /// concrete implementation to avoid attacker brute force collisions
    fn hash(&self, script: &[u8]) -> ScriptHash;

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
        history_map: BTreeMap<ScriptHash, Vec<TxSeen>>, // We want this sorted because when inserted in the write batch it's faster (see benches and test guaranteeing encoding order match struct ordering)
        utxo_created: BTreeMap<OutPoint, ScriptHash>, // We want this sorted because when inserted in the write batch it's faster (see benches and test guaranteeing encoding order match struct ordering)
    ) -> Result<()>;

    /// Reorg, reinsert the last block unspent utxos
    fn reorg(&self);

    /// Called when the initial block download is finished
    fn ibd_finished(&self);
}

impl Store for AnyStore {
    fn hash(&self, script: &[u8]) -> ScriptHash {
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
        history_map: BTreeMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: BTreeMap<OutPoint, ScriptHash>,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "db")]
            AnyStore::Db(d) => d.update(block_meta, utxo_spent, history_map, utxo_created),
            AnyStore::Mem(m) => m.update(block_meta, utxo_spent, history_map, utxo_created),
        }
    }

    fn reorg(&self) {
        match self {
            #[cfg(feature = "db")]
            AnyStore::Db(d) => d.reorg(),
            AnyStore::Mem(m) => m.reorg(),
        }
    }

    fn ibd_finished(&self) {
        match self {
            #[cfg(feature = "db")]
            AnyStore::Db(d) => d.ibd_finished(),
            AnyStore::Mem(m) => m.ibd_finished(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockMeta {
    pub height: Height,
    pub hash: BlockHash,
    pub timestamp: Timestamp,
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
