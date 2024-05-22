use anyhow::{Context, Result};
use elements::{
    encode::Encodable,
    secp256k1_zkp::rand::{thread_rng, Rng},
    OutPoint, Script,
};
use fxhash::FxHasher;
use rocksdb::{BoundColumnFamily, MergeOperands, Options, DB};

use std::{collections::HashMap, hash::Hasher, path::Path, sync::Arc};

use crate::{Height, ScriptH};
/// RocksDB wrapper for index storage

#[derive(Debug)]
pub struct DBStore {
    db: DB,
    salt: u64,
}

const UTXO_CF: &str = "utxo";
const HISTORY_CF: &str = "history";
const OTHER_CF: &str = "other";

const COLUMN_FAMILIES: &[&str] = &[UTXO_CF, HISTORY_CF, OTHER_CF];

// height key for indexed blocks
const INDEXED_KEY: &[u8] = b"I";
// height key for blockchain tip
const TIP_KEY: &[u8] = b"T";
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

    fn hasher(&self) -> FxHasher {
        let mut hasher = FxHasher::default();
        hasher.write_u64(self.salt);
        hasher
    }
    pub(crate) fn hash(&self, script: &Script) -> ScriptH {
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

    pub(crate) fn get_tip_height(&self) -> Result<u32> {
        let res = self.db.get_cf(&self.other_cf(), TIP_KEY)?;
        Ok(res
            .map(|e| u32::from_be_bytes(e.try_into().unwrap()))
            .unwrap_or(0))
    }
    pub(crate) fn set_tip_height(&self, height: u32) -> Result<()> {
        let bytes = height.to_be_bytes();
        self.db.put_cf(&self.other_cf(), TIP_KEY, bytes)?;
        Ok(())
    }

    pub(crate) fn insert_utxos(&self, adds: &HashMap<OutPoint, ScriptH>) -> Result<()> {
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

    // TODO should be remove utxos but there isn't this API in rocksdb (if became remove the update_utxos become insert_utxos)
    pub(crate) fn remove_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<ScriptH>> {
        let mut keys = Vec::with_capacity(outpoints.len());
        let mut buf = vec![0u8; 36];
        let cf = self.utxo_cf();
        for outpoint in outpoints {
            buf.clear();
            outpoint.consensus_encode(&mut buf)?;
            keys.push((&cf, buf.clone()));
        }
        let db_results = self.db.multi_get_cf(keys.clone());
        let result: Vec<_> = db_results
            .into_iter()
            .map(|e| {
                let db_val = e.unwrap().unwrap();
                let bytes = db_val.try_into().unwrap();
                u64::from_be_bytes(bytes)
            })
            .collect();

        let mut batch = rocksdb::WriteBatch::default();
        let cf = self.utxo_cf();
        for key in keys {
            batch.delete_cf(&cf, &key.1);
        }

        self.db.write(batch)?;

        Ok(result)
    }

    pub(crate) fn update_history(&self, add: &HashMap<ScriptH, Vec<Height>>) -> Result<()> {
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
    pub(crate) fn get_history(&self, scripts: &[ScriptH]) -> Result<Vec<Vec<Height>>> {
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
                    let mut c = Vec::with_capacity(e.len() / 4);
                    for chunk in e.chunks(4) {
                        c.push(u32::from_be_bytes(chunk.try_into().unwrap()));
                    }
                    result.push(c);
                }
            }
        }
        Ok(result)
    }

    pub(crate) fn update(
        &self,
        block_height: u32,

        utxo_spent: Vec<OutPoint>,
        mut history_map: HashMap<u64, Vec<u32>>,
        utxo_created: HashMap<OutPoint, u64>,
    ) {
        // should be a db tx
        let script_hashes = self.remove_utxos(&utxo_spent).unwrap();
        for script_hash in script_hashes {
            let el = history_map.entry(script_hash).or_default();
            el.push(block_height);
        }

        self.update_history(&history_map).unwrap();
        self.insert_utxos(&utxo_created).unwrap();
        self.set_to_index_height(block_height + 1).unwrap()
    }
}

fn to_be_bytes(v: &[u32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(v.len() * 4);
    for e in v {
        result.extend(e.to_be_bytes())
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

    use elements::OutPoint;

    use crate::db::get_or_init_salt;

    use super::DBStore;

    #[test]
    fn test_db() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path()).unwrap();
        assert_eq!(0, db.get_to_index_height().unwrap());
        let expected = 100;
        db.set_to_index_height(expected).unwrap();
        assert_eq!(expected, db.get_to_index_height().unwrap());

        assert_eq!(0, db.get_tip_height().unwrap());
        let expected = 100;
        db.set_tip_height(expected).unwrap();
        assert_eq!(expected, db.get_tip_height().unwrap());

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

        let mut new_history = HashMap::new();
        new_history.insert(7u64, vec![2u32, 5]);
        new_history.insert(9u64, vec![5]);
        db.update_history(&new_history).unwrap();
        let result = db.get_history(&[7]).unwrap();
        assert_eq!(result[0], vec![2u32, 5]);

        let mut new_history = HashMap::new();
        new_history.insert(7u64, vec![9]);
        db.update_history(&new_history).unwrap();
        let result = db.get_history(&[7]).unwrap();
        assert_eq!(result[0], vec![2u32, 5, 9]);
    }
}
