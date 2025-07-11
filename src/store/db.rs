use anyhow::{Context, Result};
use elements::{
    encode::Encodable,
    hashes::Hash,
    secp256k1_zkp::rand::{thread_rng, Rng},
    BlockHash, OutPoint, Script, Txid,
};
use fxhash::FxHasher;
use rocksdb::{BoundColumnFamily, MergeOperands, Options, DB};

use prefix_uvarint::PrefixVarInt;
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
const HISTORY_CF: &str = "historyv2"; // ScriptHash -> Vec<(Txid, Height(varint))>

const OTHER_CF: &str = "other";

// when height exists, it also mean the indexing happened up to that height included
const HASHES_CF: &str = "hashesv2"; // Height -> (BlockHash, Timestamp) // This is used on startup to load data into memory, not used on waterfall request

const COLUMN_FAMILIES: &[&str] = &[UTXO_CF, HISTORY_CF, OTHER_CF, HASHES_CF];

// height key for indexed blocks
// const INDEXED_KEY: &[u8] = b"I";
// height key for salting
const SALT_KEY: &[u8] = b"S";

const VEC_TX_SEEN_MAX_SIZE: usize = 41; // 32 bytes (txid) + 9 bytes (height) (most of the time height is much less)
const VEC_TX_SEEN_MIN_SIZE: usize = 33; // 32 bytes (txid) + 1 byte (height)

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
            batch.merge_cf(
                &cf,
                script_hash.to_be_bytes(),
                vec_tx_seen_to_be_bytes(new_heights),
            )
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
        let db_results = self.db.multi_get_cf(keys);
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
            let db_result = db_result?;
            match db_result {
                None => result.push(vec![]),
                Some(e) => {
                    let txs_seen = vec_tx_seen_from_be_bytes(&e)?;
                    result.push(txs_seen);
                }
            }
        }
        timer.observe_duration();
        Ok(result)
    }

    fn update(
        &self,
        block_meta: &BlockMeta,
        utxo_spent: Vec<(u32, OutPoint, Txid)>,
        history_map: HashMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: HashMap<OutPoint, ScriptHash>,
    ) -> Result<()> {
        let mut history_map = history_map;
        // TODO should be a db tx
        let only_outpoints: Vec<_> = utxo_spent.iter().map(|e| e.1).collect();
        let script_hashes = self.remove_utxos(&only_outpoints)?;
        for (script_hash, (vin, _, txid)) in script_hashes.into_iter().zip(utxo_spent) {
            let el = history_map.entry(script_hash).or_default();
            el.push(TxSeen::new(txid, block_meta.height(), -(vin as i32) - 1));
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

fn vec_tx_seen_to_be_bytes(v: &[TxSeen]) -> Vec<u8> {
    let mut result = vec![0u8; v.len() * VEC_TX_SEEN_MAX_SIZE];
    let mut offset = 0;
    for TxSeen { txid, height, .. } in v {
        result[offset..offset + 32].copy_from_slice(txid.as_byte_array());
        offset += 32;
        let bytes_len = height.encode_prefix_varint(&mut result[offset..]);
        offset += bytes_len;
    }
    result.truncate(offset);
    result
}

fn vec_tx_seen_from_be_bytes(v: &[u8]) -> Result<Vec<TxSeen>> {
    if v.is_empty() {
        return Ok(vec![]);
    }
    let mut result = Vec::with_capacity(v.len() / VEC_TX_SEEN_MIN_SIZE);
    let mut offset = 0;

    loop {
        let txid = Txid::from_slice(&v[offset..offset + 32])?;
        offset += 32;
        let (height, byte_len) = Height::decode_prefix_varint(&v[offset..])?;
        offset += byte_len;
        result.push(TxSeen::new(txid, height, 0)); // TODOV
        if offset >= v.len() {
            break;
        }
    }
    Ok(result)
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
    use std::collections::HashMap;

    use crate::store::{
        db::{get_or_init_salt, vec_tx_seen_from_be_bytes, vec_tx_seen_to_be_bytes, TxSeen},
        Store,
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
        let txs_seen = vec![TxSeen::new(txid, 2, 0), TxSeen::new(txid, 5, 0)];
        new_history.insert(7u64, txs_seen.clone());
        new_history.insert(9u64, vec![TxSeen::new(txid, 5, 0)]);
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
    #[ignore = "cannot do anymore after varint, generate random valid txseen and do the roundtrip instead"]
    fn test_vec_tx_seen_round_trip() {
        use bitcoin::key::rand::Rng;

        let mut rng = bitcoin::key::rand::thread_rng();
        let max_tests = 500; // Sensible number of tests

        for _ in 0..max_tests {
            let random_length = rng.gen_range(0..1000);
            // Generate random bytes
            let mut random_bytes = vec![0u8; random_length];
            random_bytes.fill_with(|| rng.gen());

            // Try to parse the random bytes
            match vec_tx_seen_from_be_bytes(&random_bytes) {
                Ok(parsed_tx_seen) => {
                    // If parsing succeeded, reserialize and verify round-trip
                    let reserialized = vec_tx_seen_to_be_bytes(&parsed_tx_seen);
                    assert_eq!(
                        random_bytes,
                        reserialized,
                        "Round-trip serialization failed for {} TxSeen entries",
                        parsed_tx_seen.len()
                    );
                }
                Err(_) => {
                    // Parsing failed, which is expected for random data
                    // This is fine - we're testing that valid data round-trips correctly
                }
            }
        }
    }

    #[test]
    fn test_static_txseen_round_trip() {
        let txseen = TxSeen::new(Txid::all_zeros(), 0, 0);
        let txs = vec![txseen.clone()];
        let serialized = vec_tx_seen_to_be_bytes(&txs);
        assert_eq!(serialized.len(), 33);
        let deserialized = vec_tx_seen_from_be_bytes(&serialized).unwrap();
        assert_eq!(txs, deserialized);

        let mut txseen = TxSeen::new(Txid::all_zeros(), 0, 0);
        txseen.block_hash = Some(BlockHash::all_zeros());
        txseen.block_timestamp = Some(42);
        let txs = vec![txseen.clone()];
        let serialized = vec_tx_seen_to_be_bytes(&txs);
        assert_eq!(serialized.len(), 33);
        let deserialized = vec_tx_seen_from_be_bytes(&serialized).unwrap();
        assert_ne!(
            txs, deserialized,
            "block_hash and block_timestamp must not be serialized"
        );

        let txseen = TxSeen::new(Txid::all_zeros(), 0, 0);
        let txs = vec![txseen.clone()];
        let serialized = vec_tx_seen_to_be_bytes(&txs);
        assert_eq!(serialized.len(), 33);
        // let deserialized = vec_tx_seen_from_be_bytes(&serialized).unwrap();
        // assert_eq!(
        //     txs, deserialized,
        //     "vouts must be serialized"
        // );
    }
}
