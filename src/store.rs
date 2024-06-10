use crate::{Height, ScriptHash, Timestamp};
use anyhow::Result;
use elements::{BlockHash, OutPoint, Script, Txid};
use serde::Serialize;
use std::collections::HashMap;

trait Store {
    /// Hash the given script
    ///
    /// It's in the trait cause it can be salted with some random values contained in the
    /// concrete implementation to avoid attacker brute force collisions
    fn hash(&self, script: &Script) -> ScriptHash;

    /// Iterate over blocks metadata to preload those in memory
    fn iter_hash_ts(&self) -> impl Iterator<Item = BlockMeta> + '_;

    /// Get given outpoints from the UTXO set to compute the mempool history
    fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<ScriptHash>>>;

    /// Get history of multiple (usually 20 like the gap limit) scripts hash at once
    fn get_history(&self, scripts: &[ScriptHash]) -> Result<Vec<Vec<TxSeen>>>;

    /// update the store with all the data from the last block
    fn update(
        &self,
        block_meta: BlockMeta,
        utxo_spent: Vec<(OutPoint, Txid)>,
        history_map: HashMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: HashMap<OutPoint, ScriptHash>,
    ) -> Result<()>;
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub(crate) struct TxSeen {
    pub(crate) txid: Txid,
    pub(crate) height: Height,
    pub(crate) block_hash: Option<BlockHash>,
    pub(crate) block_timestamp: Option<Timestamp>,
}
impl TxSeen {
    pub(crate) fn new(txid: Txid, height: Height) -> Self {
        Self {
            txid,
            height,
            block_hash: None,
            block_timestamp: None,
        }
    }

    pub(crate) fn mempool(txid: Txid) -> TxSeen {
        TxSeen::new(txid, 0)
    }
}

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
