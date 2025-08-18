use std::{collections::BTreeMap, hash::Hasher, sync::Mutex};

use elements::OutPoint;
use fxhash::FxHasher;

use crate::{error_panic, ScriptHash};

use super::{BlockMeta, Store, TxSeen};
use crate::V;

#[derive(Debug)]
pub struct MemoryStore {
    utxos: Mutex<BTreeMap<OutPoint, ScriptHash>>,
    history: Mutex<BTreeMap<ScriptHash, Vec<TxSeen>>>,

    // TODO memory store does not fully support reorgs
    last_block: Mutex<BTreeMap<OutPoint, ScriptHash>>,
}

impl Store for MemoryStore {
    fn hash(&self, script: &[u8]) -> ScriptHash {
        let mut hasher = FxHasher::default();
        // TODO should be salted
        hasher.write(script);
        hasher.finish()
    }

    fn iter_hash_ts(&self) -> Box<dyn Iterator<Item = BlockMeta> + '_> {
        // it's not needed to preload
        Box::new(vec![].into_iter())
    }

    fn get_utxos(
        &self,
        outpoints: &[elements::OutPoint],
    ) -> anyhow::Result<Vec<Option<ScriptHash>>> {
        let mut result = Vec::with_capacity(outpoints.len());
        for outpoint in outpoints {
            result.push(self.utxos.lock().unwrap().get(outpoint).cloned());
        }
        Ok(result)
    }

    fn get_history(
        &self,
        scripts: &[crate::ScriptHash],
    ) -> anyhow::Result<Vec<Vec<super::TxSeen>>> {
        let mut result = Vec::with_capacity(scripts.len());
        for script in scripts {
            result.push(
                self.history
                    .lock()
                    .unwrap()
                    .get(script)
                    .cloned()
                    .unwrap_or(vec![]),
            );
        }
        Ok(result)
    }

    fn update(
        &self,
        block_meta: &BlockMeta,
        utxo_spent: Vec<(u32, elements::OutPoint, elements::Txid)>,
        history_map: std::collections::BTreeMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: std::collections::BTreeMap<elements::OutPoint, ScriptHash>,
    ) -> anyhow::Result<()> {
        let mut history_map = history_map;
        // // TODO should be a db tx
        let only_outpoints: Vec<_> = utxo_spent.iter().map(|e| e.1).collect();
        let script_hashes = self.remove_utxos(&only_outpoints);

        let last_block = BTreeMap::from_iter(
            only_outpoints
                .iter()
                .cloned()
                .zip(script_hashes.iter().cloned()),
        );
        *self.last_block.lock().unwrap() = last_block; // TODO handle unwrap;

        for (script_hash, (vin, _, txid)) in script_hashes.into_iter().zip(utxo_spent) {
            let el = history_map.entry(script_hash).or_default();
            el.push(TxSeen::new(txid, block_meta.height(), V::Vin(vin)));
        }

        self.update_history(history_map);
        self.insert_utxos(&utxo_created);
        Ok(())
    }

    fn reorg(&self) {
        self.insert_utxos(&self.last_block.lock().unwrap());
    }
}

impl MemoryStore {
    fn remove_utxos(&self, outpoints: &[OutPoint]) -> Vec<ScriptHash> {
        let mut result = Vec::with_capacity(outpoints.len());
        for outpoint in outpoints {
            result.push(
                self.utxos
                    .lock()
                    .unwrap()
                    .remove(outpoint)
                    .unwrap_or_else(|| {
                        error_panic!("{outpoint} must be unspent");
                    }),
            );
        }
        result
    }
    fn update_history(&self, add: BTreeMap<ScriptHash, Vec<TxSeen>>) {
        let mut history = self.history.lock().unwrap();
        for (k, v) in add {
            history.entry(k).or_default().extend(v);
        }
    }
    fn insert_utxos(&self, adds: &BTreeMap<OutPoint, ScriptHash>) {
        self.utxos.lock().unwrap().extend(adds);
    }

    pub(crate) fn new() -> Self {
        Self {
            utxos: Mutex::new(BTreeMap::new()),
            history: Mutex::new(BTreeMap::new()),
            last_block: Mutex::new(BTreeMap::new()),
        }
    }
}
