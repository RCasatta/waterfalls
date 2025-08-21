use anyhow::{Context, Result};
use elements::{
    encode::Encodable,
    hashes::Hash,
    secp256k1_zkp::rand::{thread_rng, Rng},
    BlockHash, OutPoint, Txid,
};
use fxhash::FxHasher;
use rocksdb::{BoundColumnFamily, DBCompressionType, MergeOperands, Options, DB};

use crate::V;

use prefix_uvarint::PrefixVarInt;
use std::{
    collections::BTreeMap,
    hash::Hasher,
    path::Path,
    sync::{Arc, Mutex},
};

use crate::{
    store::{BlockMeta, Store, TxSeen},
    Height, ScriptHash,
};

/// Data for handling reorgs up to 1 block.
/// If the process halts right before a reorg, this will be lost and a reindex must happen.
#[derive(Debug, Default)]
struct ReorgData {
    /// Input spent in the last block. These are usually deleted from the db when a block is found.
    /// When there is a reorg we reinsert them in the db.
    spent: Vec<(OutPoint, ScriptHash)>,

    /// History changes from the last block. Contains the script hashes and their corresponding
    /// TxSeen entries that were added in the last block. When there is a reorg we remove
    /// these entries from the history.
    history: BTreeMap<ScriptHash, Vec<TxSeen>>,

    /// UTXOs created in the last block. When there is a reorg we remove these UTXOs
    /// from the database.
    utxos_created: BTreeMap<OutPoint, ScriptHash>,
}

/// RocksDB wrapper for index storage

#[derive(Debug)]
pub struct DBStore {
    db: DB,
    salt: u64,

    /// Reorg data for handling blockchain reorganizations
    reorg_data: Mutex<ReorgData>,
}

// Can txid be indexed by u32? At the time of writing (2025-02-06) there are about 1B txs on mainnet, so it's possible to have u32 -> txid (u32 is 4B).
// The issue is that the search must be bidirectional, so we need to store the txid -> u32 mapping in another table. It may be not worth it.

// this is needed for index building, not used on waterfall request
// In Bitcoin mainnet there are about 180M utxos, so this table would be 180M*(36+8) ~= 8GB
const UTXO_CF: &str = "utxo"; // OutPoint -> ScriptHash

// A single multiget on this is enough to compute the full get_history of a wallet.
// In Liquid mainnet the db is about 748MB (2025-02-06)
// In Bitcoin mainnet we have ~3B non-provably-unspendable-outputs (2025-02-06), so this table would be 3B*(8+32+4) = 132GB
const HISTORY_CF: &str = "historyv2"; // ScriptHash -> Vec<(Txid, Height(varint), V(varint))>

const OTHER_CF: &str = "other";

// when height exists, it also mean the indexing happened up to that height included
const HASHES_CF: &str = "hashesv2"; // Height -> (BlockHash, Timestamp) // This is used on startup to load data into memory, not used on waterfall request

const COLUMN_FAMILIES: &[&str] = &[UTXO_CF, HISTORY_CF, OTHER_CF, HASHES_CF];

// height key for indexed blocks
// const INDEXED_KEY: &[u8] = b"I";
// height key for salting
const SALT_KEY: &[u8] = b"S";

const VEC_TX_SEEN_MAX_SIZE: usize = 50; // 32 bytes (txid) + 9 bytes (height) + 9 bytes (v) (most of the time height/v is much less)
const VEC_TX_SEEN_MIN_SIZE: usize = 34; // 32 bytes (txid) + 1 byte (height) + 1 byte (v)

impl DBStore {
    fn create_cf_descriptors() -> Vec<rocksdb::ColumnFamilyDescriptor> {
        COLUMN_FAMILIES
            .iter()
            .map(|&name| {
                let mut db_opts = Options::default();

                if name == HISTORY_CF {
                    db_opts.set_merge_operator_associative("concat_merge", concat_merge);
                }

                // Set default compression to none
                db_opts.set_compression_type(DBCompressionType::None);

                // Configure compression for column families
                if name == UTXO_CF {
                    // Use no compression for level 0 to reduce zstd usage,
                    // but zstd for levels 1+ since compression ratio is high
                    let compression_levels = vec![
                        DBCompressionType::None, // Level 0
                        DBCompressionType::Zstd, // Level 1
                        DBCompressionType::Zstd, // Level 2
                        DBCompressionType::Zstd, // Level 3
                        DBCompressionType::Zstd, // Level 4
                        DBCompressionType::Zstd, // Level 5
                        DBCompressionType::Zstd, // Level 6
                    ];
                    db_opts.set_compression_per_level(&compression_levels);
                } else if name == HISTORY_CF {
                    // Use fast snappy compression only for level 6 (oldest, least accessed data)
                    let compression_levels = vec![
                        DBCompressionType::None,   // Level 0
                        DBCompressionType::None,   // Level 1
                        DBCompressionType::None,   // Level 2
                        DBCompressionType::None,   // Level 3
                        DBCompressionType::None,   // Level 4
                        DBCompressionType::None,   // Level 5
                        DBCompressionType::Snappy, // Level 6
                    ];
                    db_opts.set_compression_per_level(&compression_levels);
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
        log::info!("DB opened at path: {}", path.display());
        let salt = get_or_init_salt(&db)?;
        let store = DBStore {
            db,
            salt,
            reorg_data: Mutex::new(ReorgData::default()),
        };
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

    fn insert_utxos<'a, I>(&self, batch: &mut rocksdb::WriteBatch, adds: I) -> Result<()>
    where
        I: IntoIterator<Item = (&'a OutPoint, &'a ScriptHash)>,
        I::IntoIter: ExactSizeIterator,
    {
        let iter = adds.into_iter();
        let cf = self.utxo_cf();
        let mut key_buf = vec![0u8; 36];
        for (outpoint, script_hash) in iter {
            key_buf.clear();
            outpoint.consensus_encode(&mut key_buf)?;
            let val = script_hash.to_be_bytes();
            batch.put_cf(&cf, &key_buf, val);
        }

        Ok(())
    }

    fn remove_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<(OutPoint, ScriptHash)>> {
        let result: Vec<ScriptHash> = self
            .get_utxos(outpoints)?
            .iter()
            .enumerate()
            .map(|(i, e)| {
                e.unwrap_or_else(|| {
                    error_panic!(
                        "every utxo must exist when spent, can't find {}",
                        outpoints[i]
                    );
                })
            })
            .collect();
        let result = Vec::from_iter(outpoints.iter().cloned().zip(result.iter().cloned()));

        let mut batch = rocksdb::WriteBatch::with_capacity_bytes(outpoints.len() * 36);
        let cf = self.utxo_cf();
        let mut key_buf: Vec<u8> = vec![0u8; 36];

        for outpoint in outpoints {
            outpoint.consensus_encode(&mut key_buf)?;
            batch.delete_cf(&cf, &key_buf);
            key_buf.clear();
        }

        self.db.write(batch)?;

        Ok(result)
    }

    fn update_history(
        &self,
        batch: &mut rocksdb::WriteBatch,
        add: &BTreeMap<ScriptHash, Vec<TxSeen>>,
    ) -> Result<()> {
        if add.is_empty() {
            return Ok(());
        }
        log::debug!("update_history {add:?}");
        let cf = self.history_cf();
        let longer_vec = add
            .values()
            .map(|v| v.len())
            .max()
            .expect("add is not empty");
        let mut buf = vec![0u8; longer_vec * VEC_TX_SEEN_MAX_SIZE];

        for (script_hash, new_heights) in add {
            let len = vec_tx_seen_to_be_bytes_on_buffer(new_heights, &mut buf);
            batch.merge_cf(&cf, script_hash.to_be_bytes(), &buf[..len])
        }
        Ok(())
    }

    fn remove_history_entries(&self, to_remove: &BTreeMap<ScriptHash, Vec<TxSeen>>) -> Result<()> {
        if to_remove.is_empty() {
            return Ok(());
        }

        log::debug!("remove_history_entries {to_remove:?}");

        // Get the script hashes we need to process
        let script_hashes: Vec<ScriptHash> = to_remove.keys().cloned().collect();

        // Read current history for these script hashes
        let current_history = self.get_history(&script_hashes)?;

        let estimate_size = estimate_history_size(to_remove);
        let mut batch = rocksdb::WriteBatch::with_capacity_bytes(estimate_size);
        let cf = self.history_cf();

        for (i, script_hash) in script_hashes.iter().enumerate() {
            let entries_to_remove = &to_remove[script_hash];
            let mut current_entries = current_history[i].clone();

            // Remove the specific entries
            for entry_to_remove in entries_to_remove {
                current_entries.retain(|entry| {
                    !(entry.txid == entry_to_remove.txid
                        && entry.height == entry_to_remove.height
                        && entry.v == entry_to_remove.v)
                });
            }

            // Write back the cleaned history
            if current_entries.is_empty() {
                // If no entries left, delete the key entirely
                batch.delete_cf(&cf, script_hash.to_be_bytes());
            } else {
                // Otherwise, replace with the cleaned entries
                batch.put_cf(
                    &cf,
                    script_hash.to_be_bytes(),
                    vec_tx_seen_to_be_bytes(&current_entries),
                );
            }
        }

        self.db.write(batch)?;
        Ok(())
    }

    pub(crate) fn stats(&self) -> Option<String> {
        let mut result = String::new();

        // Column family specific information
        result.push_str("=== Column Family Stats ===\n");
        for cf_name in [UTXO_CF, HISTORY_CF] {
            if let Some(cf) = self.db.cf_handle(cf_name) {
                result.push_str(&format!("\n--- {} ---\n", cf_name));

                // column family overall stats
                if let Ok(Some(stats)) = self.db.property_value_cf(&cf, "rocksdb.stats") {
                    result.push_str(&format!("{}\n", stats));
                }

                // Size information
                if let Ok(Some(size)) = self
                    .db
                    .property_value_cf(&cf, "rocksdb.total-sst-files-size")
                {
                    let size_bytes: u64 = size.parse().unwrap_or(0);
                    result.push_str(&format!(
                        "SST Files Size: {:.2} MB\n",
                        size_bytes as f64 / 1024.0 / 1024.0
                    ));
                }

                if let Ok(Some(live_size)) = self
                    .db
                    .property_value_cf(&cf, "rocksdb.live-sst-files-size")
                {
                    let size_bytes: u64 = live_size.parse().unwrap_or(0);
                    result.push_str(&format!(
                        "Live SST Size: {:.2} MB\n",
                        size_bytes as f64 / 1024.0 / 1024.0
                    ));
                }

                // Memory usage
                if let Ok(Some(memtable_size)) = self
                    .db
                    .property_value_cf(&cf, "rocksdb.cur-size-all-mem-tables")
                {
                    let size_bytes: u64 = memtable_size.parse().unwrap_or(0);
                    result.push_str(&format!(
                        "Memtable Size: {:.2} MB\n",
                        size_bytes as f64 / 1024.0 / 1024.0
                    ));
                }

                // Number of keys
                if let Ok(Some(num_keys)) =
                    self.db.property_value_cf(&cf, "rocksdb.estimate-num-keys")
                {
                    let keys: u64 = num_keys.parse().unwrap_or(0);
                    result.push_str(&format!("Estimated Keys: {}\n", keys));
                }

                for i in 0..=6 {
                    if let Ok(Some(num)) = self
                        .db
                        .property_value_cf(&cf, &format!("rocksdb.num-files-at-level{i}"))
                    {
                        result.push_str(&format!("L{i} Number of files: {}\n", num));
                    }

                    if let Ok(Some(ratio)) = self
                        .db
                        .property_value_cf(&cf, &format!("rocksdb.compression-ratio-at-level{i}"))
                    {
                        result.push_str(&format!("L{i} compression-ratio-at-level: {ratio}\n"));
                    }
                }
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Perform manual compaction on all column families
    pub fn compact_database(&self) -> Result<()> {
        log::info!("Starting manual RocksDB compaction...");

        // Compact the default column family
        self.db.compact_range::<&[u8], &[u8]>(None, None);

        // Compact all other column families
        for cf_name in COLUMN_FAMILIES {
            if let Some(cf) = self.db.cf_handle(cf_name) {
                log::info!("Compacting column family: {}", cf_name);
                self.db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
            }
        }

        log::info!("Manual RocksDB compaction completed");
        Ok(())
    }
}

fn estimate_history_size(add: &BTreeMap<u64, Vec<TxSeen>>) -> usize {
    let mut size = 0;
    for el in add.values() {
        size += 8; // add key size
        size += el.len() * VEC_TX_SEEN_MAX_SIZE // this overshoot, but it's ok
    }
    size
}

impl Store for DBStore {
    fn hash(&self, script: &[u8]) -> ScriptHash {
        let mut hasher = self.hasher();
        hasher.write(script);
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
        history_map: BTreeMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: BTreeMap<OutPoint, ScriptHash>,
    ) -> Result<()> {
        let mut history_map = history_map;
        // TODO should be a db tx
        let only_outpoints: Vec<_> = utxo_spent.iter().map(|e| e.1).collect();
        let outpoint_script_hashes = self.remove_utxos(&only_outpoints)?;
        let script_hashes = outpoint_script_hashes.iter().map(|e| e.1);
        for (script_hash, (vin, _, txid)) in script_hashes.into_iter().zip(utxo_spent) {
            let el = history_map.entry(script_hash).or_default();
            el.push(TxSeen::new(txid, block_meta.height(), V::Vin(vin)));
        }

        self.set_hash_ts(block_meta);

        // Create a single batch with capacity for both operations
        let history_size = estimate_history_size(&history_map);
        let utxo_size = utxo_created.len() * 44; // 44 bytes per UTXO entry
        let mut batch = rocksdb::WriteBatch::with_capacity_bytes(history_size + utxo_size);

        self.update_history(&mut batch, &history_map)
            .with_context(|| format!("failed to update history for block {block_meta:?}"))?;
        self.insert_utxos(&mut batch, &utxo_created)
            .with_context(|| format!("failed to insert utxos for block {block_meta:?}"))?;

        self.db.write(batch)?;

        // Store reorg data for potential blockchain reorganization correction
        {
            let mut reorg_data = self.reorg_data.lock().unwrap();
            reorg_data.spent = outpoint_script_hashes;
            reorg_data.history = history_map;
            reorg_data.utxos_created = utxo_created;
        }

        Ok(())
    }

    fn reorg(&self) {
        let reorg_data = self.reorg_data.lock().unwrap();

        // Estimate batch size for UTXO restoration
        let utxo_restore_size = reorg_data.spent.len() * 44; // 44 bytes per UTXO entry
        let mut batch = rocksdb::WriteBatch::with_capacity_bytes(utxo_restore_size);

        // Restore UTXOs that were spent in the reorged block
        self.insert_utxos(
            &mut batch,
            reorg_data
                .spent
                .iter()
                .map(|(outpoint, script_hash)| (outpoint, script_hash)),
        )
        .unwrap(); // TODO handle unwrap;

        self.db.write(batch).unwrap(); // TODO handle unwrap;

        // Remove UTXOs that were created in the reorged block
        if !reorg_data.utxos_created.is_empty() {
            let outpoints_to_remove: Vec<OutPoint> =
                reorg_data.utxos_created.keys().cloned().collect();
            self.remove_utxos(&outpoints_to_remove).unwrap(); // TODO handle unwrap;
        }

        // Remove history entries that were added in the reorged block
        if !reorg_data.history.is_empty() {
            self.remove_history_entries(&reorg_data.history).unwrap(); // TODO handle unwrap;
        }
    }
}

fn serialize_outpoint(o: &OutPoint) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    o.consensus_encode(&mut v).expect("vec don't error");
    v
}

fn vec_tx_seen_to_be_bytes(v: &[TxSeen]) -> Vec<u8> {
    let mut result = vec![0u8; v.len() * VEC_TX_SEEN_MAX_SIZE];
    let len = vec_tx_seen_to_be_bytes_on_buffer(v, &mut result);
    result.truncate(len);
    result
}

/// panics if buf is too small
fn vec_tx_seen_to_be_bytes_on_buffer(v: &[TxSeen], buf: &mut [u8]) -> usize {
    let mut offset = 0;
    for TxSeen {
        txid, height, v, ..
    } in v
    {
        buf[offset..offset + 32].copy_from_slice(txid.as_byte_array());
        offset += 32;
        offset += height.encode_prefix_varint(&mut buf[offset..]);
        offset += v.raw().encode_prefix_varint(&mut buf[offset..]);
    }
    offset
}

fn vec_tx_seen_from_be_bytes(s: &[u8]) -> Result<Vec<TxSeen>> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    let mut result = Vec::with_capacity(s.len() / VEC_TX_SEEN_MIN_SIZE);
    let mut offset = 0;

    loop {
        let txid = Txid::from_slice(&s[offset..offset + 32])?;
        offset += 32;
        let (height, byte_len) = Height::decode_prefix_varint(&s[offset..])?;
        offset += byte_len;
        let (v, byte_len) = i32::decode_prefix_varint(&s[offset..])?;
        offset += byte_len;
        result.push(TxSeen::new(txid, height, V::from_raw(v)));
        if offset >= s.len() {
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
    let needed_bytes = existing_val.map(|e| e.len()).unwrap_or(0)
        + operands.iter().map(|e| e.len()).sum::<usize>();
    let mut result: Vec<u8> = Vec::with_capacity(needed_bytes);
    if let Some(v) = existing_val {
        result.extend_from_slice(v);
    }
    for op in operands {
        result.extend_from_slice(op);
    }
    Some(result)
}

#[cfg(test)]
mod test {
    use elements::{hashes::Hash, BlockHash, OutPoint, Txid};
    use std::collections::BTreeMap;

    use crate::store::{
        db::{
            estimate_history_size, get_or_init_salt, serialize_outpoint, vec_tx_seen_from_be_bytes,
            vec_tx_seen_to_be_bytes, TxSeen,
        },
        Store,
    };
    use crate::V;

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
        let v: BTreeMap<_, _> = vec![(o, expected), (o1, expected + 1)]
            .into_iter()
            .collect();
        let mut batch = rocksdb::WriteBatch::with_capacity_bytes(v.len() * 44);
        db.insert_utxos(&mut batch, &v).unwrap();
        db.db.write(batch).unwrap();
        let res = db.remove_utxos(&[o]).unwrap();
        assert_eq!(1, res.len());
        assert_eq!(expected, res[0].1);

        let res = db.remove_utxos(&[o1]).unwrap();
        assert_eq!(expected + 1, res[0].1);
        assert_eq!(1, res.len());

        let txid = Txid::all_zeros();

        let mut new_history = BTreeMap::new();
        let txs_seen = vec![
            TxSeen::new(txid, 2, V::Undefined),
            TxSeen::new(txid, 5, V::Undefined),
        ];
        new_history.insert(7u64, txs_seen.clone());
        new_history.insert(9u64, vec![TxSeen::new(txid, 5, V::Undefined)]);
        let history_size = estimate_history_size(&new_history);
        let mut batch = rocksdb::WriteBatch::with_capacity_bytes(history_size);
        db.update_history(&mut batch, &new_history).unwrap();
        db.db.write(batch).unwrap();
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
        let txseen = TxSeen::new(Txid::all_zeros(), 0, V::Undefined);
        let txs = vec![txseen.clone()];
        let serialized = vec_tx_seen_to_be_bytes(&txs);
        assert_eq!(serialized.len(), 34);
        let deserialized = vec_tx_seen_from_be_bytes(&serialized).unwrap();
        assert_eq!(txs, deserialized);

        let mut txseen = TxSeen::new(Txid::all_zeros(), 0, V::Undefined);
        txseen.block_hash = Some(BlockHash::all_zeros());
        txseen.block_timestamp = Some(42);
        let txs = vec![txseen.clone()];
        let serialized = vec_tx_seen_to_be_bytes(&txs);
        assert_eq!(serialized.len(), 34);
        let deserialized = vec_tx_seen_from_be_bytes(&serialized).unwrap();
        assert_ne!(
            txs, deserialized,
            "block_hash and block_timestamp must not be serialized"
        );

        let txseen = TxSeen::new(Txid::all_zeros(), 0, V::Vout(1));
        let txs = vec![txseen.clone()];
        let serialized = vec_tx_seen_to_be_bytes(&txs);
        assert_eq!(serialized.len(), 34);
        let deserialized = vec_tx_seen_from_be_bytes(&serialized).unwrap();
        assert_eq!(txs, deserialized, "v must be serialized");
    }

    #[test]
    fn test_outpoint_ordering_matches_encoding() {
        use elements::secp256k1_zkp::rand::{thread_rng, RngCore};

        let mut rng = thread_rng();

        // Create a bunch of random OutPoints
        let mut outpoints = Vec::new();
        for _ in 0..100 {
            let mut txid_bytes = [0u8; 32];
            rng.fill_bytes(&mut txid_bytes);
            let txid = Txid::from_byte_array(txid_bytes);
            let vout = rng.next_u32();
            outpoints.push(OutPoint { txid, vout });
        }

        // Add some specific test cases to ensure edge cases work
        let zero_txid = Txid::all_zeros();
        let max_txid = Txid::from_byte_array([0xff; 32]);
        outpoints.push(OutPoint {
            txid: zero_txid,
            vout: 0,
        });
        outpoints.push(OutPoint {
            txid: zero_txid,
            vout: 1,
        });
        outpoints.push(OutPoint {
            txid: zero_txid,
            vout: u32::MAX,
        });
        outpoints.push(OutPoint {
            txid: max_txid,
            vout: 0,
        });
        outpoints.push(OutPoint {
            txid: max_txid,
            vout: u32::MAX,
        });

        // Sort by PartialOrd
        let mut outpoints_by_ord = outpoints.clone();
        outpoints_by_ord.sort();

        // Create pairs of (encoded_bytes, original_outpoint) and sort by encoded bytes
        let mut outpoints_by_encoding: Vec<_> = outpoints
            .iter()
            .map(|op| (serialize_outpoint(op), *op))
            .collect();
        outpoints_by_encoding.sort_by(|a, b| a.0.cmp(&b.0));

        // Extract the outpoints from the sorted-by-encoding pairs
        let outpoints_sorted_by_encoding: Vec<_> = outpoints_by_encoding
            .into_iter()
            .map(|(_, op)| op)
            .collect();

        // Verify that both orderings are identical
        assert_eq!(
            outpoints_by_ord, outpoints_sorted_by_encoding,
            "OutPoint PartialOrd ordering must match binary encoding ordering"
        );
    }

    #[test]
    fn test_scripthash_ordering_matches_encoding() {
        use elements::secp256k1_zkp::rand::{thread_rng, Rng};

        let mut rng = thread_rng();

        // Create a bunch of random ScriptHashes (u64 values)
        let mut script_hashes = Vec::new();
        for _ in 0..100 {
            let script_hash: u64 = rng.gen();
            script_hashes.push(script_hash);
        }

        // Add some specific edge cases
        script_hashes.push(0u64); // Min value
        script_hashes.push(u64::MAX); // Max value
        script_hashes.push(1u64); // Small value
        script_hashes.push(u64::MAX - 1); // Large value

        // Sort by natural u64 ordering
        let mut script_hashes_by_ord = script_hashes.clone();
        script_hashes_by_ord.sort();

        // Create pairs of (encoded_bytes, original_script_hash) and sort by encoded bytes
        let mut script_hashes_by_encoding: Vec<_> = script_hashes
            .iter()
            .map(|&sh| (sh.to_be_bytes(), sh))
            .collect();
        script_hashes_by_encoding.sort_by(|a, b| a.0.cmp(&b.0));

        // Extract the script hashes from the sorted-by-encoding pairs
        let script_hashes_sorted_by_encoding: Vec<_> = script_hashes_by_encoding
            .into_iter()
            .map(|(_, sh)| sh)
            .collect();

        // Verify that both orderings are identical
        assert_eq!(
            script_hashes_by_ord, script_hashes_sorted_by_encoding,
            "ScriptHash (u64) natural ordering must match binary encoding ordering"
        );
    }
}
