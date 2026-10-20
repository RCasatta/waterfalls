use std::collections::{HashMap, HashSet};

use crate::{be, OutPoint, ScriptHash, TxSeen, V};

pub struct Mempool {
    txid_hashes: HashMap<crate::be::Txid, HashSet<ScriptHash>>,
    hash_txids: HashMap<ScriptHash, Vec<(crate::be::Txid, i32)>>,
    outpoints_created: HashMap<OutPoint, ScriptHash>,
}

pub struct MempoolStats {
    pub txids: usize,
    pub script_hashes: usize,
    pub positions: usize,
    pub outpoints_created: usize,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn new() -> Mempool {
        Mempool {
            txid_hashes: HashMap::new(),
            hash_txids: HashMap::new(),
            outpoints_created: HashMap::new(),
        }
    }

    /// The previous outputs spent by `txs`, in the order expected by [`Mempool::update`].
    pub fn prevouts(txs: &[(crate::be::Txid, &be::MempoolTx)]) -> Vec<OutPoint> {
        txs.iter().flat_map(|e| e.1.inputs_iter()).collect()
    }

    /// Removes `removed_txids` and adds `txs` to the mempool view.
    ///
    /// `prevouts_script_hashes` are the confirmed UTXO set lookups of [`Mempool::prevouts`] of
    /// `txs`, done by the caller so that the store isn't accessed while holding the mempool.
    pub fn update(
        &mut self,
        removed_txids: &[crate::be::Txid],
        txs: &[(crate::be::Txid, &be::MempoolTx)],
        prevouts_script_hashes: &[Option<ScriptHash>],
    ) -> HashSet<ScriptHash> {
        self.remove(removed_txids);
        self.add(txs, prevouts_script_hashes)
    }

    /// Removes `txids` from the mempool view, the ones not present are ignored.
    pub(crate) fn remove(&mut self, txids: &[crate::be::Txid]) {
        for txid in txids {
            if let Some(hashes) = self.txid_hashes.remove(txid) {
                for hash in hashes {
                    if let Some(txid_positions) = self.hash_txids.get_mut(&hash) {
                        txid_positions.retain(|(tx, _)| tx != txid);
                        if txid_positions.is_empty() {
                            self.hash_txids.remove(&hash);
                        }
                    }
                }
            }
        }
        let txid_set: HashSet<crate::be::Txid> = txids.iter().copied().collect();
        self.outpoints_created
            .retain(|k, _| !txid_set.contains(&k.txid));
    }

    fn add(
        &mut self,
        txs: &[(crate::be::Txid, &be::MempoolTx)],
        spending_script_hashes: &[Option<ScriptHash>],
    ) -> HashSet<ScriptHash> {
        // update the unconfirmed utxo set
        let outputs_created = txs.iter().flat_map(|(txid, tx)| {
            tx.output_script_hashes_iter()
                .enumerate()
                .map(move |(vout, script_hash)| (OutPoint::new(*txid, vout as u32), script_hash))
        });
        self.outpoints_created.extend(outputs_created);

        // we need to build this map for every txid all the ScriptHash involved, for output is easy
        // while for input we have to check the ScriptHash of previous output, the previous output must
        // be fetched from the db or from the mempool itself
        let mut txid_hashes: HashMap<crate::be::Txid, HashSet<ScriptHash>> =
            HashMap::with_capacity(txs.len());
        let mut txid_script_positions: HashMap<crate::be::Txid, Vec<(ScriptHash, i32)>> =
            HashMap::with_capacity(txs.len());

        debug_assert_eq!(
            spending_script_hashes.len(),
            txs.iter().map(|e| e.1.inputs_iter().count()).sum::<usize>(),
            "one prevout lookup per input expected"
        );

        let mut prevouts_index = 0usize;
        for (txid, tx) in txs {
            for (vin, previous_output) in tx.inputs_iter().enumerate() {
                let e = match spending_script_hashes[prevouts_index] {
                    Some(e) => e,
                    None => {
                        match self.outpoints_created.get(&previous_output) {
                            Some(e) => *e,
                            None => {
                                // in optimal condition should never happen, however, for example at startup we may have incomplete mempool data
                                prevouts_index += 1;
                                continue;
                            }
                        }
                    }
                };

                txid_hashes.entry(*txid).or_default().insert(e);
                // Negative position for inputs: -(vin + 1)
                txid_script_positions
                    .entry(*txid)
                    .or_default()
                    .push((e, -(vin as i32) - 1));
                prevouts_index += 1;
            }

            for (vout, script_hash) in tx.output_script_hashes_iter().enumerate() {
                let e = script_hash;
                txid_hashes.entry(*txid).or_default().insert(e);
                // Positive position for outputs: vout + 1
                txid_script_positions
                    .entry(*txid)
                    .or_default()
                    .push((e, vout as i32 + 1));
            }
        }

        let mut changed = HashSet::new();
        for (k, v) in txid_hashes {
            changed.extend(v.iter().copied());
            self.txid_hashes.entry(k).or_default().extend(&v);
        }

        // Add position information to hash_txids
        for (txid, script_positions) in txid_script_positions {
            for (script_hash, position) in script_positions {
                self.hash_txids
                    .entry(script_hash)
                    .or_default()
                    .push((txid, position));
            }
        }

        changed
    }

    pub fn append_seen(&self, script_hashes: &[ScriptHash], out: &mut [Vec<TxSeen>]) {
        for (h, tx_seens) in script_hashes.iter().zip(out.iter_mut()) {
            let txid_positions = self.hash_txids.get(h).map(Vec::as_slice).unwrap_or(&[]);
            tx_seens.reserve(txid_positions.len());
            tx_seens.extend(
                txid_positions
                    .iter()
                    .map(|(txid, position)| TxSeen::mempool(*txid, V::from_raw(*position))),
            );
        }
    }

    pub fn has_seen(&self, script_hashes: &[ScriptHash]) -> Vec<bool> {
        let mut result = Vec::with_capacity(script_hashes.len());
        for h in script_hashes {
            result.push(
                self.hash_txids
                    .get(h)
                    .is_some_and(|entries| !entries.is_empty()),
            );
        }
        result
    }

    pub(crate) fn txids_iter(&self) -> impl Iterator<Item = crate::be::Txid> + '_ {
        self.txid_hashes.keys().cloned()
    }

    pub fn stats(&self) -> MempoolStats {
        MempoolStats {
            txids: self.txid_hashes.len(),
            script_hashes: self.hash_txids.len(),
            positions: self
                .hash_txids
                .values()
                .map(|positions| positions.len())
                .sum(),
            outpoints_created: self.outpoints_created.len(),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_mempool() {}
}
