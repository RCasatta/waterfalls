use anyhow::{Context, Result};
use elements::{
    encode::Encodable,
    secp256k1_zkp::rand::{thread_rng, Rng},
    OutPoint,
};
use rocksdb::{Options, DB};

use std::{collections::HashMap, path::Path};
/// RocksDB wrapper for index storage

#[derive(Debug)]
pub struct DBStore {
    db: DB,
    salt: u64,
}

type ScriptH = u64;
type Height = u32;

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
            .map(|&name| rocksdb::ColumnFamilyDescriptor::new(name, Options::default()))
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

    fn utxo_cf(&self) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(UTXO_CF).expect("missing UTXO_CF")
    }

    fn other_cf(&self) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(OTHER_CF).expect("missing OTHER_CF")
    }

    fn history_cf(&self) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(HISTORY_CF).expect("missing HISTORY_CF")
    }

    pub(crate) fn get_indexed_height(&self) -> Result<u32> {
        let res = self.db.get_cf(self.other_cf(), INDEXED_KEY)?;
        Ok(res
            .map(|e| u32::from_be_bytes(e.try_into().unwrap()))
            .unwrap_or(0))
    }
    pub(crate) fn set_indexed_height(&self, height: u32) -> Result<()> {
        let bytes = height.to_be_bytes();
        self.db.put_cf(self.other_cf(), INDEXED_KEY, bytes)?;
        Ok(())
    }

    pub(crate) fn get_tip_height(&self) -> Result<u32> {
        let res = self.db.get_cf(self.other_cf(), TIP_KEY)?;
        Ok(res
            .map(|e| u32::from_be_bytes(e.try_into().unwrap()))
            .unwrap_or(0))
    }
    pub(crate) fn set_tip_height(&self, height: u32) -> Result<()> {
        let bytes = height.to_be_bytes();
        self.db.put_cf(self.other_cf(), TIP_KEY, bytes)?;
        Ok(())
    }

    pub(crate) fn update_utxos(
        &self,
        adds: &[(OutPoint, ScriptH)],
        removes: &[OutPoint],
    ) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        let cf = self.utxo_cf();
        let mut key_buf = vec![0u8; 36];
        for add in adds {
            key_buf.clear();
            add.0.consensus_encode(&mut key_buf)?;
            let val = add.1.to_be_bytes();
            batch.put_cf(cf, &key_buf, &val);
        }
        for remove in removes {
            key_buf.clear();
            remove.consensus_encode(&mut key_buf)?;
            batch.delete_cf(cf, &key_buf);
        }

        self.db.write(batch)?;
        Ok(())
    }
    pub(crate) fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<ScriptH>> {
        let mut keys = Vec::with_capacity(outpoints.len());
        let mut buf = vec![0u8; 36];
        let cf = self.utxo_cf();
        for outpoint in outpoints {
            println!("getting {outpoint:?}");
            buf.clear();
            outpoint.consensus_encode(&mut buf)?;
            keys.push((cf, buf.to_vec()));
        }
        let db_results = self.db.multi_get_cf(keys);
        Ok(db_results
            .into_iter()
            .map(|e| u64::from_be_bytes(e.unwrap().unwrap().try_into().unwrap()))
            .collect())
    }

    pub(crate) fn update_history(&self, add: &HashMap<ScriptH, Vec<Height>>) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        let cf = self.history_cf();

        let mut keys = Vec::with_capacity(add.len());
        for a in add {
            keys.push(*a.0);
        }
        let existing = self.get_history(&keys)?;
        for ((script_hash, new_heights), mut existing) in add.iter().zip(existing.into_iter()) {
            let mut new = false;
            for new_height in new_heights {
                if !existing.contains(new_height) {
                    existing.push(*new_height);
                    new = true;
                }
            }
            if new {
                batch.put_cf(cf, script_hash.to_be_bytes(), to_be_bytes(&existing))
            }
        }
        self.db.write(batch)?;
        Ok(())
    }
    /// get the block heights where the given scripts hash have been seen
    pub(crate) fn get_history(&self, scripts: &[ScriptH]) -> Result<Vec<Vec<Height>>> {
        let mut keys = Vec::with_capacity(scripts.len());
        let cf = self.history_cf();
        for script in scripts {
            keys.push((cf, script.to_be_bytes()));
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
    let res = db.get_cf(cf, SALT_KEY)?;
    match res {
        Some(e) => Ok(u64::from_be_bytes(e.try_into().unwrap())),
        None => {
            let mut bytes = [0u8; 8];
            thread_rng().fill(&mut bytes);
            db.put_cf(cf, SALT_KEY, bytes)?;
            get_or_init_salt(db)
        }
    }
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
        assert_eq!(0, db.get_indexed_height().unwrap());
        let expected = 100;
        db.set_indexed_height(expected).unwrap();
        assert_eq!(expected, db.get_indexed_height().unwrap());

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
        let v = vec![(o, expected), (o1, expected + 1)];
        db.update_utxos(&v, &[]).unwrap();
        let res = db.get_utxos(&[o, o1]).unwrap();
        assert_eq!(expected, res[0]);
        assert_eq!(expected + 1, res[1]);
        assert_eq!(2, res.len());
        db.update_utxos(&[], &[o]).unwrap();

        let res = db.get_utxos(&[o1]).unwrap();
        assert_eq!(expected + 1, res[0]);
        assert_eq!(1, res.len());

        let mut new_history = HashMap::new();
        new_history.insert(7u64, vec![2u32, 5]);
        new_history.insert(9u64, vec![5]);
        db.update_history(&new_history).unwrap();
        let result = db.get_history(&[7]).unwrap();
        assert_eq!(result[0], vec![2u32, 5]);
    }
}
