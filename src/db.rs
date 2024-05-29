use anyhow::{Context, Result};
use elements::{
    encode::Encodable,
    hashes::Hash,
    secp256k1_zkp::rand::{thread_rng, Rng},
    BlockHash, OutPoint, Script, Txid,
};
use fxhash::FxHasher;
use rocksdb::{BoundColumnFamily, MergeOperands, Options, DB};
use serde::Serialize;

use std::{collections::HashMap, hash::Hasher, path::Path, sync::Arc};

use crate::{Height, ScriptHash};
/// RocksDB wrapper for index storage

#[derive(Debug)]
pub struct DBStore {
    db: DB,
    salt: u64,
}

const UTXO_CF: &str = "utxo"; // OutPoint -> ScriptHash
const HISTORY_CF: &str = "history"; // ScriptHash -> Vec<(Txid, Height)>
const OTHER_CF: &str = "other";
const HASHES_CF: &str = "hashes"; // Height -> BlockHash

const COLUMN_FAMILIES: &[&str] = &[UTXO_CF, HISTORY_CF, OTHER_CF, HASHES_CF];

// height key for indexed blocks
const INDEXED_KEY: &[u8] = b"I";
// height key for salting
const SALT_KEY: &[u8] = b"S";

impl DBStore {
    fn create_cf_descriptors() -> Vec<rocksdb::ColumnFamilyDescriptor> {
        COLUMN_FAMILIES
            .iter()
            .map(|&name| {
                let mut db_opts = Options::default();
                if name == HISTORY_CF {
                    db_opts.set_merge_operator_associative("concat_merge", concat_merge);
                }
                rocksdb::ColumnFamilyDescriptor::new(name, db_opts)
            })
            .collect()
    }

    pub fn open(path: &Path) -> Result<Self> {
        let mut db_opts = Options::default();

        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let db = rocksdb::DB::open_cf_descriptors(&db_opts, path, Self::create_cf_descriptors())
            .with_context(|| format!("failed to open DB: {}", path.display()))?;
        let salt = get_or_init_salt(&db)?;
        let store = DBStore { db, salt };
        Ok(store)
    }

    fn utxo_cf(&self) -> Arc<BoundColumnFamily> {
        self.db.cf_handle(UTXO_CF).expect("missing UTXO_CF")
    }

    fn other_cf(&self) -> Arc<BoundColumnFamily> {
        self.db.cf_handle(OTHER_CF).expect("missing OTHER_CF")
    }

    fn history_cf(&self) -> Arc<BoundColumnFamily> {
        self.db.cf_handle(HISTORY_CF).expect("missing HISTORY_CF")
    }

    fn hashes_cf(&self) -> Arc<BoundColumnFamily> {
        self.db.cf_handle(HASHES_CF).expect("missing HASHES_CF")
    }

    fn hasher(&self) -> FxHasher {
        let mut hasher = FxHasher::default();
        hasher.write_u64(self.salt);
        hasher
    }
    pub(crate) fn hash(&self, script: &Script) -> ScriptHash {
        let mut hasher = self.hasher();
        hasher.write(script.as_bytes());
        hasher.finish()
    }

    /// Return the height of the block that must be indexed, in other words we have indexed up until the given block_height-1
    pub(crate) fn get_to_index_height(&self) -> Result<u32> {
        let res = self.db.get_cf(&self.other_cf(), INDEXED_KEY)?;
        Ok(res
            .map(|e| u32::from_be_bytes(e.try_into().unwrap()))
            .unwrap_or(0))
    }
    pub(crate) fn set_to_index_height(&self, height: u32) -> Result<()> {
        let bytes = height.to_be_bytes();
        self.db.put_cf(&self.other_cf(), INDEXED_KEY, bytes)?;
        Ok(())
    }

    pub(crate) fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>> {
        let res = self.db.get_cf(&self.hashes_cf(), &height.to_be_bytes())?;
        Ok(res.map(|e| BlockHash::from_slice(&e).expect("schema")))
    }
    pub(crate) fn set_block_hash(&self, height: u32, hash: BlockHash) -> Result<()> {
        self.db.put_cf(
            &self.hashes_cf(),
            height.to_be_bytes(),
            hash.as_byte_array(),
        )?;
        Ok(())
    }
    pub(crate) fn _get_multi_block_hash(&self, height: &[u32]) -> Result<Vec<BlockHash>> {
        let cf = self.hashes_cf();
        let keys: Vec<_> = height.iter().map(|e| (&cf, e.to_be_bytes())).collect();
        let res = self.db.multi_get_cf(keys);
        let res: Vec<_> = res
            .into_iter()
            .map(|e| {
                BlockHash::from_slice(&e.transpose().expect("hash must be there").unwrap()).unwrap()
            }) // TODO unwraps
            .collect();
        Ok(res)
    }
    pub(crate) fn tip(&self) -> Result<Height> {
        let mut iter = self
            .db
            .iterator_cf(&self.hashes_cf(), rocksdb::IteratorMode::End);

        Ok(match iter.next().transpose()? {
            Some(el) => Height::from_be_bytes(el.0.as_ref().try_into().expect("schema")),
            None => 0,
        })
    }

    pub(crate) fn insert_utxos(&self, adds: &HashMap<OutPoint, ScriptHash>) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        let cf = self.utxo_cf();
        let mut key_buf = vec![0u8; 36];
        for add in adds {
            key_buf.clear();
            add.0.consensus_encode(&mut key_buf)?;
            let val = add.1.to_be_bytes();
            batch.put_cf(&cf, &key_buf, val);
        }

        self.db.write(batch)?;
        Ok(())
    }

    pub(crate) fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<ScriptHash>>> {
        let mut keys = Vec::with_capacity(outpoints.len());
        let cf = self.utxo_cf();
        for outpoint in outpoints {
            keys.push((&cf, serialize_outpoint(outpoint)));
        }
        let db_results = self.db.multi_get_cf(keys.clone());
        let result: Vec<_> = db_results
            .into_iter()
            .map(|e| {
                e.unwrap().map(|e| {
                    let bytes = e.try_into().unwrap();
                    u64::from_be_bytes(bytes)
                })
            })
            .collect();
        Ok(result)
    }

    // TODO should be remove utxos but there isn't this API in rocksdb (if became remove the update_utxos become insert_utxos)
    pub(crate) fn remove_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<ScriptHash>> {
        let result: Vec<_> = self
            .get_utxos(outpoints)?
            .iter()
            .enumerate()
            .map(|(i, e)| {
                if e.is_none() {
                    println!("can't find {}", outpoints[i]);
                }
                e.expect("every utxo must exist when spent")
            })
            .collect();

        let mut batch = rocksdb::WriteBatch::default();
        let cf = self.utxo_cf();
        let mut keys = Vec::with_capacity(outpoints.len());
        for outpoint in outpoints {
            keys.push((&cf, serialize_outpoint(outpoint)));
        }
        for key in keys {
            batch.delete_cf(&cf, &key.1);
        }

        self.db.write(batch)?;

        Ok(result)
    }

    pub(crate) fn update_history(&self, add: &HashMap<ScriptHash, Vec<TxSeen>>) -> Result<()> {
        if add.is_empty() {
            return Ok(());
        }
        // println!("update_history {add:?}");
        // TODO use merge https://docs.rs/rocksdb/latest/rocksdb/merge_operator/index.html
        let mut batch = rocksdb::WriteBatch::default();
        let cf = self.history_cf();

        let mut keys = Vec::with_capacity(add.len());
        for a in add {
            keys.push(*a.0);
        }
        for (script_hash, new_heights) in add {
            batch.merge_cf(&cf, script_hash.to_be_bytes(), to_be_bytes(new_heights))
        }
        self.db.write(batch)?;
        Ok(())
    }
    /// get the block heights where the given scripts hash have been seen
    pub(crate) fn get_history(&self, scripts: &[ScriptHash]) -> Result<Vec<Vec<TxSeen>>> {
        if scripts.is_empty() {
            return Ok(vec![]);
        }
        let mut keys = Vec::with_capacity(scripts.len());
        let cf = self.history_cf();
        for script in scripts {
            keys.push((&cf, script.to_be_bytes()));
        }
        let db_results = self.db.multi_get_cf(keys);
        let mut result = Vec::with_capacity(scripts.len());
        for db_result in db_results {
            let db_result = db_result.unwrap();
            match db_result {
                None => result.push(vec![]),
                Some(e) => {
                    let mut txs_seen = from_be_bytes(&e);
                    for tx in txs_seen.iter_mut() {
                        // TODO headers list must be in memory
                        tx.block_hash = self.get_block_hash(tx.height)?;
                    }
                    result.push(txs_seen)
                }
            }
        }
        Ok(result)
    }

    pub(crate) fn update(
        &self,
        block_height: Height,
        utxo_spent: Vec<(OutPoint, Txid)>,
        mut history_map: HashMap<u64, Vec<TxSeen>>,
        utxo_created: HashMap<OutPoint, u64>,
    ) {
        // TODO should be a db tx
        let only_outpoints: Vec<_> = utxo_spent.iter().map(|e| e.0).collect();
        let script_hashes = self.remove_utxos(&only_outpoints).unwrap();
        for (script_hash, (_, txid)) in script_hashes.into_iter().zip(utxo_spent) {
            let el = history_map.entry(script_hash).or_default();
            el.push(TxSeen::new(txid, block_height));
        }

        self.update_history(&history_map).unwrap();
        self.insert_utxos(&utxo_created).unwrap();
        self.set_to_index_height(block_height + 1).unwrap()
    }
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub(crate) struct TxSeen {
    txid: Txid,
    height: Height,
    block_hash: Option<BlockHash>,
}
impl TxSeen {
    pub(crate) fn new(txid: Txid, height: Height) -> Self {
        Self {
            txid,
            height,
            block_hash: None,
        }
    }

    pub(crate) fn mempool(txid: Txid) -> TxSeen {
        Self {
            txid,
            height: 0,
            block_hash: None,
        }
    }
}

fn serialize_outpoint(o: &OutPoint) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    o.consensus_encode(&mut v).expect("vec don't error");
    v
}

fn to_be_bytes(v: &[TxSeen]) -> Vec<u8> {
    let mut result = Vec::with_capacity(v.len() * 36);
    for TxSeen {
        txid,
        height,
        block_hash: _,
    } in v
    {
        result.extend(txid.as_byte_array());
        result.extend(height.to_be_bytes());
    }
    result
}

fn from_be_bytes(v: &[u8]) -> Vec<TxSeen> {
    let mut result = Vec::with_capacity(v.len() / 36);

    for chunk in v.chunks(36) {
        let txid = Txid::from_slice(&chunk[..32]).unwrap();
        let height = Height::from_be_bytes(chunk[32..].try_into().unwrap());
        result.push(TxSeen {
            txid,
            height,
            block_hash: None,
        })
    }
    result
}

fn get_or_init_salt(db: &DB) -> Result<u64> {
    let cf = db.cf_handle(OTHER_CF).expect("missing OTHER_CF");
    let res = db.get_cf(&cf, SALT_KEY)?;
    match res {
        Some(e) => Ok(u64::from_be_bytes(e.try_into().unwrap())),
        None => {
            let mut bytes = [0u8; 8];
            thread_rng().fill(&mut bytes);
            db.put_cf(&cf, SALT_KEY, bytes)?;
            get_or_init_salt(db)
        }
    }
}

fn concat_merge(
    _new_key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let mut result: Vec<u8> = Vec::with_capacity(operands.len());
    if let Some(v) = existing_val {
        for e in v {
            result.push(*e)
        }
    }
    for op in operands {
        for e in op {
            result.push(*e)
        }
    }
    Some(result)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use elements::{hashes::Hash, BlockHash, OutPoint, Txid};

    use crate::db::{get_or_init_salt, TxSeen};

    use super::DBStore;

    #[test]
    fn test_db() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path()).unwrap();
        assert_eq!(0, db.get_to_index_height().unwrap());
        let expected = 100;
        db.set_to_index_height(expected).unwrap();
        assert_eq!(expected, db.get_to_index_height().unwrap());

        assert_eq!(0, db.tip().unwrap());

        let salt = get_or_init_salt(&db.db).unwrap();
        assert_ne!(salt, 0);
        let salt2 = get_or_init_salt(&db.db).unwrap();
        assert_eq!(salt, salt2);

        let o = OutPoint::default();
        let o1 = {
            let mut o1 = o;
            o1.vout = 1;
            o1
        };
        let expected = 42u64;
        let v: HashMap<_, _> = vec![(o, expected), (o1, expected + 1)]
            .into_iter()
            .collect();
        db.insert_utxos(&v).unwrap();
        let res = db.remove_utxos(&[o]).unwrap();
        assert_eq!(1, res.len());
        assert_eq!(expected, res[0]);

        let res = db.remove_utxos(&[o1]).unwrap();
        assert_eq!(expected + 1, res[0]);
        assert_eq!(1, res.len());

        let txid = Txid::all_zeros();

        let mut new_history = HashMap::new();
        let txs_seen = vec![TxSeen::new(txid, 2), TxSeen::new(txid, 5)];
        new_history.insert(7u64, txs_seen.clone());
        new_history.insert(9u64, vec![TxSeen::new(txid, 5)]);
        db.update_history(&new_history).unwrap();
        let result = db.get_history(&[7]).unwrap();
        assert_eq!(result[0], txs_seen);

        // let mut new_history = HashMap::new();
        // new_history.insert(7u64, vec![9]);
        // db.update_history(&new_history).unwrap();
        // let result = db.get_history(&[7]).unwrap();
        // assert_eq!(result[0], vec![2u32, 5, 9]);

        assert_eq!(db.tip().unwrap(), 0);

        db.set_block_hash(0, BlockHash::all_zeros()).unwrap();
        db.set_block_hash(1, BlockHash::all_zeros()).unwrap();
        db.set_block_hash(2, BlockHash::all_zeros()).unwrap();

        assert_eq!(db.get_block_hash(3).unwrap(), None);
        assert_eq!(db.get_block_hash(2).unwrap(), Some(BlockHash::all_zeros()));
        assert_eq!(db.tip().unwrap(), 2);

        let r = db._get_multi_block_hash(&[0, 1, 2]).unwrap();
        assert_eq!(r, vec![BlockHash::all_zeros(); 3]);
    }
}
