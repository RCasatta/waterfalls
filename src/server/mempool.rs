use std::{
    collections::{HashMap, HashSet},
    iter,
};

use elements::{OutPoint, Transaction, Txid};

use crate::{
    store::{AnyStore, Store},
    ScriptHash,
};

pub struct Mempool {
    txid_hashes: HashMap<Txid, HashSet<ScriptHash>>,
    hash_txids: HashMap<ScriptHash, Vec<Txid>>,
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
                    self.hash_txids.remove(&hash);
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

        let prevouts: Vec<OutPoint> = txs
            .iter()
            .flat_map(|e| e.input.iter())
            .map(|i| i.previous_output)
            .collect();
        let spending_script_hashes = db.get_utxos(&prevouts).unwrap();

        let mut prevouts_index = 0usize;
        for (txid, tx) in txs_map {
            for input in tx.input.iter() {
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
                prevouts_index += 1;
            }

            for output in tx.output.iter() {
                let e = db.hash(&output.script_pubkey);
                txid_hashes.entry(txid).or_default().insert(e);
            }
        }

        for (k, v) in txid_hashes {
            self.txid_hashes.entry(k).or_default().extend(&v);
            for e in v {
                self.hash_txids.entry(e).or_default().push(k);
            }
        }
    }

    pub fn seen(&self, script_hashes: &[ScriptHash]) -> Vec<Vec<Txid>> {
        let mut result = vec![];
        for h in script_hashes {
            let r = self.hash_txids.get(h).cloned().unwrap_or(vec![]);
            result.push(r)
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
