use std::collections::{HashMap, HashSet};

use elements::{Transaction, Txid};

use crate::{db::DBStore, ScriptHash};

pub(crate) struct Mempool(HashMap<Txid, HashSet<ScriptHash>>);

impl Mempool {
    pub(crate) fn new() -> Mempool {
        Mempool(HashMap::new())
    }

    pub(crate) fn remove(&mut self, _txids: &[Txid]) {
        todo!()
    }

    pub(crate) fn add(&mut self, _db: &DBStore, _txs: &[Transaction]) {
        todo!()
    }

    pub(crate) fn contains(&self, _script_hashes: &[ScriptHash]) -> Vec<Vec<Txid>> {
        todo!()
    }
}
