use std::{collections::BTreeMap, hash::Hasher, sync::Mutex};

use fxhash::FxHasher;

use crate::{error_panic, Height, OutPoint, ScriptHash};

use super::{BlockMeta, Store, TxSeen};
use crate::V;

#[derive(Debug)]
pub struct MemoryStore {
    utxos: Mutex<BTreeMap<OutPoint, ScriptHash>>,
    history: Mutex<BTreeMap<ScriptHash, Vec<TxSeen>>>,
    reorg_data: Mutex<BTreeMap<Height, MemoryReorgData>>,
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

    fn get_utxos(&self, outpoints: &[OutPoint]) -> anyhow::Result<Vec<Option<ScriptHash>>> {
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

    fn has_history(&self, scripts: &[crate::ScriptHash]) -> anyhow::Result<Vec<bool>> {
        let history = self.history.lock().unwrap();
        let mut result = Vec::with_capacity(scripts.len());
        for script in scripts {
            result.push(
                history
                    .get(script)
                    .is_some_and(|entries| !entries.is_empty()),
            );
        }
        Ok(result)
    }

    fn update(
        &self,
        block_meta: &BlockMeta,
        utxo_spent: Vec<(u32, OutPoint, crate::be::Txid)>,
        history_map: std::collections::BTreeMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: std::collections::BTreeMap<OutPoint, ScriptHash>,
    ) -> anyhow::Result<()> {
        let mut history_map = history_map;
        let only_outpoints: Vec<_> = utxo_spent.iter().map(|e| e.1).collect();
        let script_hashes = self.remove_utxos(&only_outpoints);

        let spent = Vec::from_iter(
            only_outpoints
                .iter()
                .cloned()
                .zip(script_hashes.iter().cloned()),
        );

        for (script_hash, (vin, _, txid)) in script_hashes.into_iter().zip(utxo_spent) {
            let el = history_map.entry(script_hash).or_default();
            el.push(TxSeen::new(txid, block_meta.height(), V::Vin(vin)));
        }

        // TODO: handle unwraps on the lock
        self.reorg_data.lock().unwrap().insert(
            block_meta.height(),
            MemoryReorgData {
                spent,
                history: history_map.clone(),
                utxos_created: utxo_created.clone(),
            },
        );
        self.update_history(history_map);
        self.insert_utxos(&utxo_created);
        Ok(())
    }

    fn reorg(&self, height: crate::Height) {
        let reorg_data = self
            .reorg_data
            .lock()
            .unwrap()
            .remove(&height)
            .unwrap_or_else(|| {
                error_panic!("missing reorg data for height {height}");
            });
        self.insert_utxos_vec(&reorg_data.spent);
        self.remove_utxos_map(&reorg_data.utxos_created);
        self.remove_history_entries(reorg_data.history);
    }

    fn ibd_finished(&self) {}
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
    fn insert_utxos_vec(&self, adds: &[(OutPoint, ScriptHash)]) {
        self.utxos.lock().unwrap().extend(adds.iter().cloned());
    }
    fn remove_utxos_map(&self, removes: &BTreeMap<OutPoint, ScriptHash>) {
        let mut utxos = self.utxos.lock().unwrap();
        for outpoint in removes.keys() {
            utxos.remove(outpoint);
        }
    }
    fn remove_history_entries(&self, removes: BTreeMap<ScriptHash, Vec<TxSeen>>) {
        let mut history = self.history.lock().unwrap();
        for (script_hash, entries_to_remove) in removes {
            let existing = history.get_mut(&script_hash).unwrap_or_else(|| {
                error_panic!("missing history for script hash {script_hash}");
            });
            let new_len = existing
                .len()
                .checked_sub(entries_to_remove.len())
                .unwrap_or_else(|| {
                    error_panic!(
                        "history underflow for script hash {script_hash}: existing {} remove {}",
                        existing.len(),
                        entries_to_remove.len()
                    );
                });
            if existing[new_len..] != entries_to_remove {
                error_panic!("history mismatch while reorging script hash {script_hash}");
            }
            existing.truncate(new_len);
            if existing.is_empty() {
                history.remove(&script_hash);
            }
        }
    }

    pub(crate) fn new() -> Self {
        Self {
            utxos: Mutex::new(BTreeMap::new()),
            history: Mutex::new(BTreeMap::new()),
            reorg_data: Mutex::new(BTreeMap::new()),
        }
    }
}

#[derive(Debug)]
struct MemoryReorgData {
    spent: Vec<(OutPoint, ScriptHash)>,
    history: BTreeMap<ScriptHash, Vec<TxSeen>>,
    utxos_created: BTreeMap<OutPoint, ScriptHash>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::be::Txid;
    use std::str::FromStr;

    #[test]
    fn test_memory_store_reorg_restores_utxos_and_history() {
        let store = MemoryStore::new();
        let source_script_hash = 11;
        let recipient_script_hash = 22;
        let one = "1111111111111111111111111111111111111111111111111111111111111111";
        let source_outpoint = OutPoint::new(crate::be::Txid::from_str(one).unwrap(), 0);
        let two = "2222222222222222222222222222222222222222222222222222222222222222";
        let created_outpoint = OutPoint::new(crate::be::Txid::from_str(two).unwrap(), 1);
        store
            .utxos
            .lock()
            .unwrap()
            .insert(source_outpoint, source_script_hash);

        let three = "3333333333333333333333333333333333333333333333333333333333333333";
        let block_meta = BlockMeta::new(1, elements::BlockHash::from_str(three).unwrap(), 123);
        let four = "4444444444444444444444444444444444444444444444444444444444444444";
        let spending_txid = Txid::from_str(four).unwrap();
        let mut history_map = BTreeMap::new();
        history_map.insert(
            recipient_script_hash,
            vec![TxSeen::new(spending_txid, block_meta.height(), V::Vout(1))],
        );
        let mut utxo_created = BTreeMap::new();
        utxo_created.insert(created_outpoint, recipient_script_hash);

        store
            .update(
                &block_meta,
                vec![(0, source_outpoint, spending_txid)],
                history_map,
                utxo_created,
            )
            .unwrap();

        assert_eq!(store.utxos.lock().unwrap().get(&source_outpoint), None);
        assert_eq!(
            store.utxos.lock().unwrap().get(&created_outpoint),
            Some(&recipient_script_hash)
        );
        assert_eq!(
            store.history.lock().unwrap().get(&source_script_hash),
            Some(&vec![TxSeen::new(
                spending_txid,
                block_meta.height(),
                V::Vin(0)
            )])
        );
        assert_eq!(
            store.history.lock().unwrap().get(&recipient_script_hash),
            Some(&vec![TxSeen::new(
                spending_txid,
                block_meta.height(),
                V::Vout(1)
            )])
        );

        store.reorg(block_meta.height());

        assert_eq!(
            store.utxos.lock().unwrap().get(&source_outpoint),
            Some(&source_script_hash)
        );
        assert_eq!(store.utxos.lock().unwrap().get(&created_outpoint), None);
        assert!(store.history.lock().unwrap().is_empty());
    }
}
