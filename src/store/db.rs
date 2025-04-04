use anyhow::{Context, Result};
use elements::{
    encode::Encodable,
    hashes::Hash,
    secp256k1_zkp::rand::{thread_rng, Rng},
    BlockHash, OutPoint, Script, Txid,
};
use fxhash::FxHasher;
use rocksdb::{BoundColumnFamily, MergeOperands, Options, DB};

use std::{collections::HashMap, hash::Hasher, path::Path, sync::Arc};

use crate::{
    store::{BlockMeta, Store, TxSeen},
    Height, ScriptHash,
};
/// RocksDB wrapper for index storage

#[derive(Debug)]
pub struct DBStore {
    db: DB,
    salt: u64,
}

// Can txid be indexed by u32? At the time of writing (2025-02-06) there are about 1B txs on mainnet, so it's possible to have u32 -> txid (u32 is 4B).
// The issue is that the search must be bidirectional, so we need to store the txid -> u32 mapping in another table. It may be not worth it.

// this is needed for index building, not used on waterfall request
// TODO Can we change this to Txid -> Vec<ScriptHash> (with script hash = 0 if spent) ? This would allow to compute a descriptor utxos via another multiget at the cost of complex/slower indexing.
// In Bitcoin mainnet there are about 180M utxos, so this table would be 180M*(36+8) ~= 8GB
const UTXO_CF: &str = "utxo"; // OutPoint -> ScriptHash

// A single multiget on this is enough to compute the full get_history of a wallet.
// In Liquid mainnet the db is about 748MB (2025-02-06)
// In Bitcoin mainnet we have ~3B non-provably-unspendable-outputs (2025-02-06), so this table would be 3B*(8+32+4) = 132GB
const HISTORY_CF: &str = "history"; // ScriptHash -> Vec<(Txid, Height)>

const OTHER_CF: &str = "other";

// when height exists, it also mean the indexing happened up to that height included
const HASHES_CF: &str = "hashesv2"; // Height -> (BlockHash, Timestamp) // This is used on startup to load data into memory, not used on waterfall request

const COLUMN_FAMILIES: &[&str] = &[UTXO_CF, HISTORY_CF, OTHER_CF, HASHES_CF];

// height key for indexed blocks
// const INDEXED_KEY: &[u8] = b"I";
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
    fn set_hash_ts(&self, meta: &BlockMeta) {
        let mut buffer = Vec::with_capacity(36);
        buffer.extend(meta.hash().as_byte_array());
        buffer.extend(&meta.timestamp().to_be_bytes());
        self.db
            .put_cf(&self.hashes_cf(), meta.height().to_be_bytes(), buffer)
            .unwrap();
    }

    fn insert_utxos(&self, adds: &HashMap<OutPoint, ScriptHash>) -> Result<()> {
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

    fn remove_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<ScriptHash>> {
        let result: Vec<_> = self
            .get_utxos(outpoints)?
            .iter()
            .enumerate()
            .map(|(i, e)| {
                if e.is_none() {
                    log::error!("can't find {}", outpoints[i]);
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

    fn update_history(&self, add: &HashMap<ScriptHash, Vec<TxSeen>>) -> Result<()> {
        if add.is_empty() {
            return Ok(());
        }
        log::debug!("update_history {add:?}");
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
}

impl Store for DBStore {
    fn hash(&self, script: &Script) -> ScriptHash {
        let mut hasher = self.hasher();
        hasher.write(script.as_bytes());
        hasher.finish()
    }

    fn iter_hash_ts(&self) -> Box<dyn Iterator<Item = BlockMeta> + '_> {
        let mode = rocksdb::IteratorMode::Start;
        let opts = rocksdb::ReadOptions::default();
        Box::new(
            self.db
                .iterator_cf_opt(&self.hashes_cf(), opts, mode)
                .map(|kv| {
                    let kv = kv.expect("iterator failed");
                    let height = u32::from_be_bytes((&kv.0[..]).try_into().expect("schema"));
                    let hash = BlockHash::from_slice(&kv.1[..32]).expect("schema");
                    let ts = u32::from_be_bytes((&kv.1[32..]).try_into().expect("schema"));
                    BlockMeta::new(height, hash, ts)
                }),
        )
    }

    fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<ScriptHash>>> {
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

    /// get the block heights where the given scripts hash have been seen
    fn get_history(&self, scripts: &[ScriptHash]) -> Result<Vec<Vec<TxSeen>>> {
        let timer = crate::WATERFALLS_DB_HISTORY_HISTOGRAM
            .with_label_values(&["all"])
            .start_timer();

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
                    let txs_seen = from_be_bytes(&e);
                    result.push(txs_seen)
                }
            }
        }
        timer.observe_duration();
        Ok(result)
    }

    fn update(
        &self,
        block_meta: &BlockMeta,
        utxo_spent: Vec<(OutPoint, Txid)>,
        history_map: HashMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: HashMap<OutPoint, ScriptHash>,
    ) -> Result<()> {
        let mut history_map = history_map;
        // TODO should be a db tx
        let only_outpoints: Vec<_> = utxo_spent.iter().map(|e| e.0).collect();
        let script_hashes = self.remove_utxos(&only_outpoints)?;
        for (script_hash, (_, txid)) in script_hashes.into_iter().zip(utxo_spent) {
            let el = history_map.entry(script_hash).or_default();
            el.push(TxSeen::new(txid, block_meta.height()));
        }

        self.set_hash_ts(block_meta);
        self.update_history(&history_map)?;
        self.insert_utxos(&utxo_created)?;

        Ok(())
    }
}

fn serialize_outpoint(o: &OutPoint) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    o.consensus_encode(&mut v).expect("vec don't error");
    v
}

fn to_be_bytes(v: &[TxSeen]) -> Vec<u8> {
    let mut result = Vec::with_capacity(v.len() * 36);
    for TxSeen { txid, height, .. } in v {
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
        result.push(TxSeen::new(txid, height))
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
    use elements::{hashes::Hash, BlockHash, OutPoint, Txid};
    use std::{collections::HashMap, str::FromStr};

    use crate::store::{
        db::{get_or_init_salt, TxSeen},
        BlockMeta, Store,
    };

    use super::DBStore;

    #[test]
    fn test_db() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path()).unwrap();

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

        // assert_eq!(db.tip().unwrap(), 0);

        // db.set_hash_ts(0, BlockHash::all_zeros(), 4).unwrap();
        // db.set_hash_ts(1, BlockHash::all_zeros(), 5).unwrap();
        // db.set_hash_ts(2, BlockHash::all_zeros(), 6).unwrap();

        // assert_eq!(db.get_block_hash(3).unwrap(), None);
        // assert_eq!(db.get_block_hash(2).unwrap(), Some(BlockHash::all_zeros()));
        // assert_eq!(db.tip().unwrap(), 2);

        // let r = db._get_multi_block_hash(&[0, 1, 2]).unwrap();
        // assert_eq!(r, vec![BlockHash::all_zeros(); 3]);
    }

    #[test]
    fn test_spent_different_block() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path()).unwrap();

        let mut history_map_1 = HashMap::new();
        let mut utxo_created_1 = HashMap::new();
        let mut utxo_spent_1 = vec![];

        let txid_1 =
            Txid::from_str("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
                .unwrap();
        let outpoint_1 = OutPoint::new(txid_1, 0);
        let utxos: HashMap<_, _> = vec![(outpoint_1, 1u64)].into_iter().collect();
        db.insert_utxos(&utxos).unwrap();

        // Simulate a transaction that spends the UTXO created above
        let txid_2 =
            Txid::from_str("0c52d2526a5c9f00e9fb74afd15dd3caaf17c823159a514f929ae25193a43a52")
                .unwrap();
        let el_2 = history_map_1.entry(7u64).or_insert(vec![]);
        el_2.push(TxSeen::new(txid_2, 1));

        let outpoint_2 = OutPoint::new(txid_2, 0);
        utxo_created_1.insert(outpoint_2, 7u64);

        utxo_spent_1.push((outpoint_1, txid_2));

        // Update block 1
        let meta_1 = BlockMeta::new(1, BlockHash::all_zeros(), 1);
        db.update(&meta_1, utxo_spent_1, history_map_1, utxo_created_1)
            .unwrap();

        let result = db.get_history(&[7]).unwrap();
        assert_eq!(result[0], vec![TxSeen::new(txid_2, 1)]);

        // Start block 2
        let mut history_map_2 = HashMap::new();
        let mut utxo_created_2 = HashMap::new();
        let mut utxo_spent_2 = vec![];

        // Simulate a transaction that spends the UTXO created above
        let txid_3 =
            Txid::from_str("f3581d726b4cf9b62f0ff9ad3b39c01f8ac3e8528dec4fd0cc656aac8c084032")
                .unwrap();
        let el_3 = history_map_2.entry(8u64).or_insert(vec![]);
        el_3.push(TxSeen::new(txid_3, 2));

        let outpoint_3 = OutPoint::new(txid_3, 0);
        utxo_created_2.insert(outpoint_3, 8u64);

        utxo_spent_2.push((outpoint_2, txid_3));

        // Update block 2
        let meta_2 = BlockMeta::new(2, BlockHash::all_zeros(), 2);
        db.update(&meta_2, utxo_spent_2, history_map_2, utxo_created_2)
            .unwrap();

        let result_7 = db.get_history(&[7]).unwrap();
        assert_eq!(
            result_7[0],
            vec![TxSeen::new(txid_2, 1), TxSeen::new(txid_3, 2)]
        );

        let result_8 = db.get_history(&[8]).unwrap();
        assert_eq!(result_8[0], vec![TxSeen::new(txid_3, 2)]);
    }

    #[test]
    fn test_spent_same_block() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path()).unwrap();

        let mut history_map = HashMap::new();
        let mut utxo_created = HashMap::new();
        let mut utxo_spent = vec![];

        let txid_1 =
            Txid::from_str("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
                .unwrap();
        let outpoint_1 = OutPoint::new(txid_1, 0);
        let utxos: HashMap<_, _> = vec![(outpoint_1, 1u64)].into_iter().collect();
        db.insert_utxos(&utxos).unwrap();

        // Simulate a transaction that spends the UTXO created above
        let txid_2 =
            Txid::from_str("0c52d2526a5c9f00e9fb74afd15dd3caaf17c823159a514f929ae25193a43a52")
                .unwrap();
        let el_2 = history_map.entry(7u64).or_insert(vec![]);
        el_2.push(TxSeen::new(txid_2, 1));

        let outpoint_2 = OutPoint::new(txid_2, 0);
        utxo_created.insert(outpoint_2, 7u64);

        // Simulate a transaction that spends the UTXO created above
        let txid_3 =
            Txid::from_str("f3581d726b4cf9b62f0ff9ad3b39c01f8ac3e8528dec4fd0cc656aac8c084032")
                .unwrap();
        let el_3 = history_map.entry(8u64).or_insert(vec![]);
        el_3.push(TxSeen::new(txid_3, 1));

        let outpoint_3 = OutPoint::new(txid_3, 0);
        utxo_created.insert(outpoint_3, 8u64);
        utxo_spent.push((outpoint_1, txid_2));

        // Removed as its spent in the same block
        utxo_created.remove(&outpoint_2);
        //utxo_spent.push((outpoint_2, txid_3));

        // We need to insert the history of the spend for the previous output script
        let el_4 = history_map.entry(7u64).or_insert(vec![]);
        el_4.push(TxSeen::new(txid_3, 1));

        // Update block
        let meta = BlockMeta::new(1, BlockHash::all_zeros(), 1);
        db.update(&meta, utxo_spent, history_map, utxo_created)
            .unwrap();

        let result_7 = db.get_history(&[7]).unwrap();
        assert_eq!(
            result_7[0],
            vec![TxSeen::new(txid_2, 1), TxSeen::new(txid_3, 1)]
        );

        let result_8 = db.get_history(&[8]).unwrap();
        assert_eq!(result_8[0], vec![TxSeen::new(txid_3, 1)]);
    }
}
