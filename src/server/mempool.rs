use std::{
    collections::{HashMap, HashSet},
    iter,
};

use elements::{OutPoint, Transaction, Txid};

use crate::{
    store::{AnyStore, Store},
    ScriptHash, TxSeen,
};

pub struct Mempool {
    txid_hashes: HashMap<Txid, HashSet<ScriptHash>>,
    hash_txids: HashMap<ScriptHash, Vec<(Txid, i32)>>,
    outpoints_created: HashMap<OutPoint, ScriptHash>,
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

    pub fn remove(&mut self, txids: &[Txid]) {
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
            .retain(|k, _| !txids.contains(&k.txid));
    }

    pub fn add(&mut self, db: &AnyStore, txs: &[Transaction]) {
        let txs_map: HashMap<Txid, &Transaction> = txs.iter().map(|tx| (tx.txid(), tx)).collect();

        // update the unconfirmed utxo set
        let outputs_created = txs_map
            .iter()
            .flat_map(|(txid, tx)| tx.output.iter().enumerate().zip(iter::repeat(txid)))
            .map(|((vout, txout), txid)| {
                (
                    OutPoint::new(*txid, vout as u32),
                    db.hash(&txout.script_pubkey),
                )
            });
        self.outpoints_created.extend(outputs_created);

        // we need to build this map for every txid all the ScriptHash involved, for output is easy
        // while for input we have to check the ScriptHash of previous output, the previous output must
        // be fetched from the db or from the mempool itself
        let mut txid_hashes: HashMap<Txid, HashSet<ScriptHash>> = HashMap::new();
        let mut txid_script_positions: HashMap<Txid, Vec<(ScriptHash, i32)>> = HashMap::new();

        let prevouts: Vec<OutPoint> = txs
            .iter()
            .flat_map(|e| e.input.iter())
            .map(|i| i.previous_output)
            .collect();
        let spending_script_hashes = db.get_utxos(&prevouts).unwrap();

        let mut prevouts_index = 0usize;
        for (txid, tx) in txs_map {
            for (vin, input) in tx.input.iter().enumerate() {
                let e = match spending_script_hashes[prevouts_index] {
                    Some(e) => e,
                    None => {
                        match self.outpoints_created.get(&input.previous_output) {
                            Some(e) => *e,
                            None => {
                                // in optimal condition should never happen, however, for example at startup we may have incomplete mempool data
                                prevouts_index += 1;
                                continue;
                            }
                        }
                    }
                };

                txid_hashes.entry(txid).or_default().insert(e);
                // Negative position for inputs: -(vin + 1)
                txid_script_positions
                    .entry(txid)
                    .or_default()
                    .push((e, -(vin as i32) - 1));
                prevouts_index += 1;
            }

            for (vout, output) in tx.output.iter().enumerate() {
                let e = db.hash(&output.script_pubkey);
                txid_hashes.entry(txid).or_default().insert(e);
                // Positive position for outputs: vout + 1
                txid_script_positions
                    .entry(txid)
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
            let txid_positions = self.hash_txids.get(h).cloned().unwrap_or(vec![]);
            let tx_seens: Vec<TxSeen> = txid_positions
                .into_iter()
                .map(|(txid, position)| TxSeen::mempool(txid, position))
                .collect();
            result.push(tx_seens);
        }
        result
    }

    pub(crate) fn txids(&self) -> HashSet<Txid> {
        self.txid_hashes.keys().cloned().collect()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_mempool() {}
}
