use std::{
    collections::{HashMap, HashSet},
};

use crate::{
    be,
    store::{AnyStore, Store},
    OutPoint, ScriptHash, TxSeen, V,
};

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

    pub fn update(
        &mut self,
        db: &AnyStore,
        removed_txids: &[crate::be::Txid],
        txs: &[(crate::be::Txid, be::Transaction)],
    ) {
        self.remove(removed_txids);
        self.add(db, txs);
    }

    fn remove(&mut self, txids: &[crate::be::Txid]) {
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
        self.outpoints_created
            .retain(|k, _| !txids.contains(&k.txid.into()));
    }

    fn add(&mut self, db: &AnyStore, txs: &[(crate::be::Txid, be::Transaction)]) {
        // update the unconfirmed utxo set
        let outputs_created = txs
            .iter()
            .flat_map(|(txid, tx)| tx.outputs_iter().enumerate().map(move |(vout, txout)| {
                (
                    OutPoint::new(*txid, vout as u32),
                    db.hash(txout.script_pubkey_bytes()),
                )
            }));
        self.outpoints_created.extend(outputs_created);

        // we need to build this map for every txid all the ScriptHash involved, for output is easy
        // while for input we have to check the ScriptHash of previous output, the previous output must
        // be fetched from the db or from the mempool itself
        let mut txid_hashes: HashMap<crate::be::Txid, HashSet<ScriptHash>> =
            HashMap::with_capacity(txs.len());
        let mut txid_script_positions: HashMap<crate::be::Txid, Vec<(ScriptHash, i32)>> =
            HashMap::with_capacity(txs.len());

        let prevouts: Vec<OutPoint> = txs
            .iter()
            .flat_map(|e| e.1.inputs_iter())
            .map(|i| i.previous_output())
            .collect();
        let spending_script_hashes = db.get_utxos(&prevouts).unwrap();

        let mut prevouts_index = 0usize;
        for (txid, tx) in txs {
            for (vin, input) in tx.inputs_iter().enumerate() {
                let e = match spending_script_hashes[prevouts_index] {
                    Some(e) => e,
                    None => {
                        match self.outpoints_created.get(&input.previous_output()) {
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

            for (vout, output) in tx.outputs_iter().enumerate() {
                let e = db.hash(output.script_pubkey_bytes());
                txid_hashes.entry(*txid).or_default().insert(e);
                // Positive position for outputs: vout + 1
                txid_script_positions
                    .entry(*txid)
                    .or_default()
                    .push((e, vout as i32 + 1));
            }
        }

        for (k, v) in txid_hashes {
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
    }

    pub fn seen(&self, script_hashes: &[ScriptHash]) -> Vec<Vec<TxSeen>> {
        let mut result = vec![];
        for h in script_hashes {
            let txid_positions = self.hash_txids.get(h).map(Vec::as_slice).unwrap_or(&[]);
            let tx_seens: Vec<TxSeen> = txid_positions
                .into_iter()
                .map(|(txid, position)| TxSeen::mempool(*txid, V::from_raw(*position)))
                .collect();
            result.push(tx_seens);
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
            positions: self.hash_txids.values().map(|positions| positions.len()).sum(),
            outpoints_created: self.outpoints_created.len(),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_mempool() {}
}
