use anyhow::{Context, Result};
use elements::{
    encode::Encodable,
    hashes::Hash,
    secp256k1_zkp::rand::{thread_rng, Rng},
    BlockHash,
};
use fxhash::FxHasher;
use rocksdb::{
    BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DBCompressionType,
    DBPinnableSlice, MergeOperands, Options, DB,
};

use crate::V;

use super::reorg_data::ReorgData;
use prefix_uvarint::PrefixVarInt;
use std::{
    collections::BTreeMap,
    hash::Hasher,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use crate::{
    error_panic,
    store::{BlockMeta, Store, TxSeen},
    Height, OutPoint, ScriptHash,
};

/// RocksDB wrapper for index storage

#[derive(Debug)]
pub struct DBStore {
    db: DB,
    script_hasher: ScriptHasher,

    /// Whether we are in Initial Block Download mode.
    /// During initial block download we skip reorg data writes, since reorgs are
    /// extremely unlikely for old blocks and the data is only needed near tip.
    ///
    /// Every process start begins in IBD mode, so the blocks task turns it off as soon as
    /// the block being indexed is within `reorg_data_keep_heights` of the node tip, not
    /// only when the tip is reached: a block indexed without reorg data can never be
    /// rolled back, and the blocks indexed while catching up after a restart are exactly
    /// the ones a reorg is most likely to hit.
    ibd: AtomicBool,

    /// Number of recent block heights to keep reorg data for. Older reorg data is automatically deleted.
    reorg_data_keep_heights: u32,
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

// Reorg data for each block to enable rollback on chain reorganization
const REORG_CF: &str = "reorg"; // Height -> ReorgData (serialized)

const COLUMN_FAMILIES: &[&str] = &[UTXO_CF, HISTORY_CF, OTHER_CF, HASHES_CF, REORG_CF];

// height key for indexed blocks
// const INDEXED_KEY: &[u8] = b"I";
// salt of the script hash, its meaning depends on the format version, see `ScriptHasher`
const SALT_KEY: &[u8] = b"S";

/// Format version of the database, see [`read_format_version`]. Only in databases of a format
/// version above 1, which binaries released before it existed must not open: they don't list
/// this column family, and RocksDB refuses to open a database without all its column families.
const META_CF: &str = "meta";
const FORMAT_VERSION_KEY: &[u8] = b"V";

/// Highest format version this binary can open.
///
/// 1. Script hashes computed by FxHash with a salt, see `ScriptHasher::SaltedFx`.
/// 2. Script hashes computed by SipHash-2-4 with a key, see `ScriptHasher::KeyedSip`.
const FORMAT_VERSION: u32 = 2;

const VEC_TX_SEEN_MAX_SIZE: usize = 50; // 32 bytes (txid) + 9 bytes (height) + 9 bytes (v) (most of the time height/v is much less)
const VEC_TX_SEEN_MIN_SIZE: usize = 34; // 32 bytes (txid) + 1 byte (height) + 1 byte (v)

impl DBStore {
    fn raw_history_multi_get(
        &self,
        scripts: &[ScriptHash],
    ) -> Result<Vec<Option<DBPinnableSlice<'_>>>> {
        if scripts.is_empty() {
            return Ok(vec![]);
        }

        // Benchmarks on temporary RocksDB instances consistently showed that sorting
        // the history keys before batched_multi_get_cf is a net win, including the
        // production-shaped 20-lookups case, even after reordering results back.
        let cf = self.history_cf();
        let mut indexed_keys: Vec<_> = scripts
            .iter()
            .enumerate()
            .map(|(index, script)| (index, script.to_be_bytes()))
            .collect();
        indexed_keys.sort_unstable_by_key(|(_, key)| *key);
        let sorted_results =
            self.db
                .batched_multi_get_cf(&cf, indexed_keys.iter().map(|(_, key)| key), true);
        let mut reordered: Vec<Option<DBPinnableSlice<'_>>> = std::iter::repeat_with(|| None)
            .take(scripts.len())
            .collect();
        for ((index, _), result) in indexed_keys.into_iter().zip(sorted_results.into_iter()) {
            reordered[index] = result.map_err(anyhow::Error::from)?;
        }

        Ok(reordered)
    }

    fn create_cf_descriptors(shared_db_cache_mb: u64) -> Vec<rocksdb::ColumnFamilyDescriptor> {
        let cache_size = (shared_db_cache_mb * 1024 * 1024) as usize;
        // HyperClockCache is lock-free, reducing mutex contention under concurrent reads.
        // estimated_entry_charge=0 uses the auto-growing variant, which dynamically sizes
        // its internal table — safer than a fixed estimate when caching mixed-size entries
        // (data blocks, index blocks, filter blocks).
        // NOTE: a zero cache size is used to mean "disabled". Building a HyperClockCache
        // with zero bytes can crash in native RocksDB code.
        let shared_cache = (cache_size > 0).then(|| Cache::new_hyper_clock_cache(cache_size, 0));

        COLUMN_FAMILIES
            .iter()
            .map(|&name| {
                let mut db_opts = Options::default();

                // Set default compression to none
                db_opts.set_compression_type(DBCompressionType::None);

                if name == UTXO_CF || name == HISTORY_CF {
                    // Use shared cache instead of optimize_for_point_lookup
                    let mut block_opts = BlockBasedOptions::default();
                    if let Some(cache) = shared_cache.as_ref() {
                        block_opts.set_block_cache(cache);
                    }

                    // Configure for point lookups similar to optimize_for_point_lookup
                    block_opts.set_block_size(16 * 1024); // 16KB blocks
                    block_opts.set_cache_index_and_filter_blocks(true);
                    block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

                    if name == HISTORY_CF {
                        // bloom filter are useful only for gets with a key miss,
                        // which happens a lot for history and never for utxo.
                        // TODO actually not true for utxo_only query
                        block_opts.set_bloom_filter(10.0, true);
                    }

                    db_opts.set_block_based_table_factory(&block_opts);
                }

                if name == HISTORY_CF {
                    db_opts.set_merge_operator_associative("concat_merge", concat_merge);
                }

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
                }

                rocksdb::ColumnFamilyDescriptor::new(name, db_opts)
            })
            .collect()
    }

    /// A new database hashes scripts with keyed SipHash. A database created by a previous
    /// release, with the legacy salted script hash, fails to open unless
    /// `allow_legacy_script_hash` is set, see `--allow-legacy-script-hash`.
    pub fn open(
        path: &Path,
        shared_db_cache_mb: u64,
        enable_statistics: bool,
        reorg_data_keep_heights: u32,
        allow_legacy_script_hash: bool,
    ) -> Result<Self> {
        let mut db_opts = Options::default();

        // Enable statistics collection for detailed metrics including bloom filter stats
        if enable_statistics {
            db_opts.enable_statistics();
        }
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        let parallelism = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1)
            .min(4) as i32;
        log::info!("Setting RocksDB parallelism to {} threads", parallelism);
        db_opts.increase_parallelism(parallelism);
        db_opts.set_max_background_jobs(parallelism);

        // A new database, for which listing fails, has no META_CF either.
        let has_meta_cf =
            DB::list_cf(&db_opts, path).is_ok_and(|cfs| cfs.iter().any(|cf| cf == META_CF));
        let mut cf_descriptors = Self::create_cf_descriptors(shared_db_cache_mb);
        if has_meta_cf {
            cf_descriptors.push(ColumnFamilyDescriptor::new(META_CF, Options::default()));
        }
        let db = rocksdb::DB::open_cf_descriptors(&db_opts, path, cf_descriptors)
            .with_context(|| format!("failed to open DB: {}", path.display()))?;
        log::info!("DB opened at path: {}", path.display());
        let format_version = read_format_version(&db)
            .with_context(|| format!("failed to open DB: {}", path.display()))?;
        if format_version > FORMAT_VERSION {
            anyhow::bail!(
                "failed to open DB: {}: its format version is {format_version}, it was created by \
                 a newer waterfalls supporting it, this one supports up to {FORMAT_VERSION}",
                path.display()
            );
        }
        let script_hasher =
            get_or_init_script_hasher(&db, format_version, allow_legacy_script_hash)
                .with_context(|| format!("failed to open DB: {}", path.display()))?;
        log::info!("script hash: {}", script_hasher.name());
        let store = DBStore {
            db,
            script_hasher,
            ibd: AtomicBool::new(true),
            reorg_data_keep_heights,
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

    /// Add block hash and timestamp to an existing batch (does not write to DB).
    fn set_hash_ts_batch(&self, batch: &mut rocksdb::WriteBatch, meta: &BlockMeta) {
        let mut buffer = Vec::with_capacity(36);
        buffer.extend(meta.hash().as_byte_array());
        buffer.extend(&meta.timestamp().to_be_bytes());
        batch.put_cf(&self.hashes_cf(), meta.height().to_be_bytes(), buffer);
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

    /// Look up UTXOs and return their script hashes, panicking if any UTXO doesn't exist.
    /// This is a read-only operation.
    fn get_utxos_for_spending(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<(OutPoint, ScriptHash)>> {
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
        Ok(Vec::from_iter(
            outpoints.iter().cloned().zip(result.iter().cloned()),
        ))
    }

    /// Add UTXO deletions to an existing batch (does not write to DB).
    fn delete_utxos_batch<'a, I>(&self, batch: &mut rocksdb::WriteBatch, outpoints: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a OutPoint>,
    {
        let cf = self.utxo_cf();
        let mut key_buf: Vec<u8> = vec![0u8; 36];

        for outpoint in outpoints {
            key_buf.clear();
            outpoint.consensus_encode(&mut key_buf)?;
            batch.delete_cf(&cf, &key_buf);
        }
        Ok(())
    }

    /// Remove UTXOs from the database and return their script hashes.
    /// This writes immediately to the database (non-atomic with other operations).
    #[cfg(test)]
    fn remove_utxos(&self, outpoints: &[OutPoint]) -> Result<Vec<(OutPoint, ScriptHash)>> {
        let result = self.get_utxos_for_spending(outpoints)?;

        let mut batch = rocksdb::WriteBatch::with_capacity_bytes(outpoints.len() * 36);
        self.delete_utxos_batch(&mut batch, outpoints.iter())?;
        self.write(batch)?;

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

    fn remove_history_entries_batch(
        &self,
        batch: &mut rocksdb::WriteBatch,
        to_remove: &BTreeMap<ScriptHash, Vec<TxSeen>>,
    ) -> Result<()> {
        const REORG_HISTORY_CHUNK_SIZE: usize = 20;

        if to_remove.is_empty() {
            return Ok(());
        }

        log::info!("remove history entries: {}", to_remove.len());

        let cf = self.history_cf();

        for script_hashes in to_remove
            .keys()
            .collect::<Vec<_>>()
            .chunks(REORG_HISTORY_CHUNK_SIZE)
        {
            let script_hashes: Vec<ScriptHash> = script_hashes.iter().map(|e| **e).collect();
            let current_history = self.get_history(&script_hashes)?;

            for (script_hash, mut current_entries) in
                script_hashes.iter().zip(current_history.into_iter())
            {
                let entries_to_remove = &to_remove[script_hash];

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
        }
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
                        if num.parse::<u64>().unwrap_or(0) == 0 {
                            // avoid printing if there are no files at this level
                            continue;
                        }
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

    fn write(&self, batch: rocksdb::WriteBatch) -> Result<()> {
        self.db.write(batch)?;
        Ok(())
    }

    fn _reorg(&self, height: Height) -> Result<()> {
        log::warn!("reorg: reading reorg data for height {}", height);

        // Read reorg data from database
        let reorg_cf = self.db.cf_handle(REORG_CF).expect("missing REORG_CF");
        let reorg_bytes = self
            .db
            .get_cf(&reorg_cf, height.to_be_bytes())?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No reorg data found for height {}. This likely means the server restarted \
                    after indexing a block that was later reorged. A reindex may be required.",
                    height
                )
            })?;

        // Deserialize reorg data
        let reorg_data = ReorgData::from_bytes(&reorg_bytes)
            .with_context(|| format!("failed to deserialize reorg data for height {}", height))?;

        log::info!(
            "reorg: restoring {} spent UTXOs, removing {} created UTXOs, removing {} history entries",
            reorg_data.spent.len(),
            reorg_data.utxos_created.len(),
            reorg_data.history.len()
        );

        let mut batch = rocksdb::WriteBatch::default();

        // Restore UTXOs that were spent in the reorged block
        self.insert_utxos(
            &mut batch,
            reorg_data
                .spent
                .iter()
                .map(|(outpoint, script_hash)| (outpoint, script_hash)),
        )?;

        // Remove UTXOs that were created in the reorged block
        if !reorg_data.utxos_created.is_empty() {
            self.delete_utxos_batch(&mut batch, reorg_data.utxos_created.keys())?;
        }

        // Remove history entries that were added in the reorged block
        if !reorg_data.history.is_empty() {
            self.remove_history_entries_batch(&mut batch, &reorg_data.history)?;
        }

        // Delete the rolled-back block metadata and the reorg data since it's been applied
        batch.delete_cf(&self.hashes_cf(), height.to_be_bytes());
        batch.delete_cf(&reorg_cf, height.to_be_bytes());

        self.write(batch)?;

        log::info!(
            "reorg: database rollback completed successfully for height {}",
            height
        );

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
        self.script_hasher.hash(script)
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
        let cf = self.utxo_cf();
        let keys: Vec<_> = outpoints.iter().map(serialize_outpoint).collect();
        let db_results = self.db.batched_multi_get_cf(&cf, keys.iter(), false);
        let result: Vec<_> = db_results
            .into_iter()
            .map(|e| {
                e.unwrap().map(|e| {
                    let bytes = e.as_ref().try_into().unwrap();
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

        let db_results = self.raw_history_multi_get(scripts)?;
        let mut result = Vec::with_capacity(scripts.len());
        for db_result in db_results {
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

    fn has_history(&self, scripts: &[ScriptHash]) -> Result<Vec<bool>> {
        let timer = crate::WATERFALLS_DB_HISTORY_HISTOGRAM
            .with_label_values(&["all"])
            .start_timer();

        let result = self
            .raw_history_multi_get(scripts)?
            .into_iter()
            .map(|entry| entry.is_some_and(|bytes| !bytes.is_empty()))
            .collect();

        timer.observe_duration();
        Ok(result)
    }

    fn update(
        &self,
        block_meta: &BlockMeta,
        utxo_spent: Vec<(u32, OutPoint, crate::be::Txid)>,
        history_map: BTreeMap<ScriptHash, Vec<TxSeen>>,
        utxo_created: BTreeMap<OutPoint, ScriptHash>,
    ) -> Result<Vec<ScriptHash>> {
        let mut history_map = history_map;

        // First, read the script hashes for spent UTXOs (read-only operation)
        let only_outpoints: Vec<_> = utxo_spent.iter().map(|e| e.1).collect();
        let outpoint_script_hashes = self.get_utxos_for_spending(&only_outpoints)?;

        // Build the history entries for spending transactions
        let script_hashes = outpoint_script_hashes.iter().map(|e| e.1);
        for (script_hash, (vin, _, txid)) in script_hashes.into_iter().zip(utxo_spent) {
            let el = history_map.entry(script_hash).or_default();
            el.push(TxSeen::new(txid, block_meta.height(), V::Vin(vin)));
        }

        let changed_script_hashes = history_map.keys().copied().collect::<Vec<_>>();

        // Create a single batch for ALL writes (atomic operation)
        // This ensures that either all data is written or none, preventing
        // inconsistent state if the process is killed mid-update.
        let history_size = estimate_history_size(&history_map);
        let utxo_delete_size = only_outpoints.len() * 36;
        let utxo_create_size = utxo_created.len() * 44;
        let hash_ts_size = 40; // 4 bytes key + 36 bytes value
        let mut batch = rocksdb::WriteBatch::with_capacity_bytes(
            history_size + utxo_delete_size + utxo_create_size + hash_ts_size,
        );

        // Add all operations to the batch
        self.delete_utxos_batch(&mut batch, only_outpoints.iter())
            .with_context(|| format!("failed to delete spent utxos for block {block_meta:?}"))?;
        self.set_hash_ts_batch(&mut batch, block_meta);
        self.update_history(&mut batch, &history_map)
            .with_context(|| format!("failed to update history for block {block_meta:?}"))?;
        self.insert_utxos(&mut batch, &utxo_created)
            .with_context(|| format!("failed to insert utxos for block {block_meta:?}"))?;

        // Store reorg data for potential blockchain reorganization correction
        // Skip during IBD (Initial Block Download) as reorgs are extremely unlikely for old blocks
        // and this saves significant write overhead during initial sync.
        // A block written here without reorg data cannot be rolled back later, so the
        // caller must call `ibd_finished` before indexing any block that is within
        // `reorg_data_keep_heights` of the node tip (see `threads::blocks`).
        if !self.ibd.load(Ordering::Relaxed) {
            // Create ReorgData and persist it to the database
            let reorg_data = ReorgData {
                spent: outpoint_script_hashes,
                history: history_map,
                utxos_created: utxo_created,
            };

            // Serialize and save reorg data
            let reorg_bytes = reorg_data.to_bytes().with_context(|| {
                format!("failed to serialize reorg data for block {block_meta:?}")
            })?;
            let reorg_cf = self.db.cf_handle(REORG_CF).expect("missing REORG_CF");
            batch.put_cf(&reorg_cf, block_meta.height().to_be_bytes(), reorg_bytes);

            // Delete old reorg data that exceeds the retention period
            let current_height = block_meta.height();
            if current_height >= self.reorg_data_keep_heights {
                let height_to_delete = current_height - self.reorg_data_keep_heights;
                batch.delete_cf(&reorg_cf, height_to_delete.to_be_bytes());
            }
        }

        // Single atomic write (includes reorg data)
        self.write(batch)?;

        Ok(changed_script_hashes)
    }

    fn reorg(&self, height: Height) {
        if let Err(e) = self._reorg(height) {
            error_panic!("reorg failed: {e}");
        }
    }

    fn ibd_finished(&self) {
        if self.ibd.swap(false, Ordering::Relaxed) {
            log::info!("Initial block download finished, enabling reorg data writes");
        }
    }
}

fn serialize_outpoint(o: &OutPoint) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    o.consensus_encode(&mut v).expect("vec don't error");
    v
}

pub(super) fn vec_tx_seen_to_be_bytes(v: &[TxSeen]) -> Vec<u8> {
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

pub(super) fn vec_tx_seen_from_be_bytes(s: &[u8]) -> Result<Vec<TxSeen>> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    let mut result = Vec::with_capacity(s.len() / VEC_TX_SEEN_MIN_SIZE);
    let mut offset = 0;

    loop {
        let txid = crate::be::Txid::from_slice(&s[offset..offset + 32])?;
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

/// Format version of `db`: the value stored in [`META_CF`], or 1 for a database without it.
///
/// A database gets a format version above 1, and the column family storing it, when it needs a
/// binary knowing that version to be read correctly.
fn read_format_version(db: &DB) -> Result<u32> {
    let Some(cf) = db.cf_handle(META_CF) else {
        return Ok(1);
    };
    let version = db
        .get_cf(&cf, FORMAT_VERSION_KEY)?
        .ok_or_else(|| anyhow::anyhow!("missing format version"))?;
    let version: [u8; 4] = version
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid format version length"))?;
    Ok(u32::from_be_bytes(version))
}

/// Reads the script hasher of the database, or creates a keyed one with a random key for a new
/// database.
///
/// The script hash is the key of the history and is stored in the UTXO set, so it cannot change
/// without reindexing: an existing database keeps the one it was created with. A database
/// created by a previous release uses the legacy salted script hash, and is refused unless
/// `allow_legacy_script_hash` is set: switching to the keyed one needs a reindex.
///
/// The format version tells how the stored salt is used: the 8 bytes of the FxHash salt in
/// version 1, the 16 bytes of the SipHash-2-4 key in version 2. A keyed database is created with
/// format version 2, so that previous releases, which would read its salt as an FxHash one,
/// refuse to open it.
fn get_or_init_script_hasher(
    db: &DB,
    format_version: u32,
    allow_legacy_script_hash: bool,
) -> Result<ScriptHasher> {
    let cf = db.cf_handle(OTHER_CF).expect("missing OTHER_CF");
    match (format_version, db.get_cf(&cf, SALT_KEY)?) {
        (2, Some(key)) => {
            let key: [u8; 16] = key
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid script hash key length"))?;
            Ok(ScriptHasher::keyed(key))
        }
        (1, Some(salt)) if allow_legacy_script_hash => {
            let salt: [u8; 8] = salt
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid script hash salt length"))?;
            log::warn!(
                "using the legacy script hash of a database created by a previous release, \
                 reindex into a new --db-dir to switch to the keyed one"
            );
            Ok(ScriptHasher::SaltedFx(u64::from_be_bytes(salt)))
        }
        (1, Some(_)) => anyhow::bail!(
            "the database was created by a previous release, with the legacy script hash: \
             point --db-dir to an empty directory to reindex with the keyed script hash, or \
             start with --allow-legacy-script-hash to keep using this database"
        ),
        (1, None) => {
            let mut key = [0u8; 16];
            thread_rng().fill(&mut key);
            db.create_cf(META_CF, &Options::default())?;
            let meta_cf = db.cf_handle(META_CF).expect("just created");
            // The version and the key are written together: a database has both or neither.
            let mut batch = rocksdb::WriteBatch::default();
            batch.put_cf(&meta_cf, FORMAT_VERSION_KEY, 2u32.to_be_bytes());
            batch.put_cf(&cf, SALT_KEY, key);
            db.write(batch)?;
            Ok(ScriptHasher::keyed(key))
        }
        (version, None) => {
            anyhow::bail!("missing script hash salt in a database of format version {version}")
        }
        // Versions above FORMAT_VERSION are refused before getting here.
        (version, Some(_)) => anyhow::bail!("unknown format version {version}"),
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

/// How a database hashes scripts, chosen when it is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptHasher {
    /// FxHash seeded with a random 64-bit salt, in databases created by previous releases
    SaltedFx(u64),
    /// SipHash-2-4 keyed with a random 128-bit key
    KeyedSip { k0: u64, k1: u64 },
}

impl ScriptHasher {
    fn keyed(key: [u8; 16]) -> Self {
        let (k0, k1) = key.split_at(8);
        ScriptHasher::KeyedSip {
            k0: u64::from_le_bytes(k0.try_into().expect("8 bytes")),
            k1: u64::from_le_bytes(k1.try_into().expect("8 bytes")),
        }
    }

    fn hash(&self, script: &[u8]) -> ScriptHash {
        match self {
            ScriptHasher::SaltedFx(salt) => {
                let mut hasher = FxHasher::default();
                hasher.write_u64(*salt);
                hasher.write(script);
                hasher.finish()
            }
            ScriptHasher::KeyedSip { k0, k1 } => {
                elements::hashes::siphash24::Hash::hash_to_u64_with_keys(*k0, *k1, script)
            }
        }
    }

    fn name(&self) -> &'static str {
        match self {
            ScriptHasher::SaltedFx(_) => "salted FxHash",
            ScriptHasher::KeyedSip { .. } => "keyed SipHash-2-4",
        }
    }
}

#[cfg(test)]
mod test {
    use elements::{hashes::Hash, BlockHash, Txid};
    use rocksdb::DB;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicBool, Ordering},
    };

    use crate::store::{
        db::{
            estimate_history_size, get_or_init_script_hasher, serialize_outpoint,
            vec_tx_seen_from_be_bytes, vec_tx_seen_to_be_bytes, TxSeen,
        },
        BlockMeta, Store,
    };
    use crate::OutPoint;
    use crate::V;

    use super::{
        read_format_version, DBStore, ScriptHasher, COLUMN_FAMILIES, FORMAT_VERSION,
        FORMAT_VERSION_KEY, META_CF, OTHER_CF, REORG_CF, SALT_KEY,
    };

    /// Adds a META_CF storing `version` to the database at `path`.
    fn write_format_version(path: &std::path::Path, version: u32) {
        let mut opts = rocksdb::Options::default();
        opts.create_missing_column_families(true);
        let cfs = COLUMN_FAMILIES.iter().copied().chain([META_CF]);
        let db = DB::open_cf(&opts, path, cfs).unwrap();
        let cf = db.cf_handle(META_CF).unwrap();
        db.put_cf(&cf, FORMAT_VERSION_KEY, version.to_be_bytes())
            .unwrap();
    }

    fn column_families(path: &std::path::Path) -> Vec<String> {
        DB::list_cf(&rocksdb::Options::default(), path).unwrap()
    }

    /// Creates a database as previous releases did: format version 1, salted script hash.
    fn create_legacy_database(path: &std::path::Path, salt: u64) {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open_cf(&opts, path, COLUMN_FAMILIES).unwrap();
        let cf = db.cf_handle(OTHER_CF).unwrap();
        db.put_cf(&cf, SALT_KEY, salt.to_be_bytes()).unwrap();
    }

    #[test]
    fn format_version_one_without_meta_cf() {
        let tempdir = tempfile::TempDir::new().unwrap();
        create_legacy_database(tempdir.path(), 42);
        drop(DBStore::open(tempdir.path(), 64, false, 6, true).unwrap());
        // Databases of version 1 stay readable by binaries without META_CF.
        assert!(!column_families(tempdir.path()).contains(&META_CF.to_string()));

        write_format_version(tempdir.path(), 1);
        DBStore::open(tempdir.path(), 64, false, 6, true).unwrap();
    }

    #[test]
    fn newer_format_version_refused() {
        let tempdir = tempfile::TempDir::new().unwrap();
        drop(DBStore::open(tempdir.path(), 64, false, 6, false).unwrap());
        write_format_version(tempdir.path(), FORMAT_VERSION + 1);

        let err = DBStore::open(tempdir.path(), 64, false, 6, false).unwrap_err();
        assert!(format!("{err:#}").contains("newer waterfalls"), "{err:#}");
    }

    #[test]
    fn test_db_hash_compatibility() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        // creating explicitly to set the salt to a fixed value
        let db = DBStore {
            db: DB::open(&opts, tempdir.path()).unwrap(),
            script_hasher: ScriptHasher::SaltedFx(0),
            ibd: AtomicBool::new(true),
            reorg_data_keep_heights: 6,
        };
        let hash = db.hash(b"test");
        assert_eq!(hash, 2879782050633127044);

        // The keyed script hash of existing databases must not change either.
        let key: [u8; 16] = std::array::from_fn(|i| i as u8);
        let hash = ScriptHasher::keyed(key).hash(b"test");
        // SipHash-2-4 of "test" with key 00..0f, matching the reference implementation
        assert_eq!(hash, 2771506328522617498);
    }

    #[test]
    fn new_database_uses_keyed_script_hash() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path(), 64, false, 6, false).unwrap();
        let hasher = db.script_hasher;
        assert!(matches!(hasher, ScriptHasher::KeyedSip { .. }));
        let hash = db.hash(b"test");
        // The key is stored as the salt, the format version tells how to use it.
        let other_cf = db.db.cf_handle(OTHER_CF).unwrap();
        let salt = db.db.get_cf(&other_cf, SALT_KEY).unwrap().unwrap();
        assert_eq!(salt.len(), 16);
        drop(other_cf);
        drop(db);
        assert!(column_families(tempdir.path()).contains(&META_CF.to_string()));

        // The database keeps its key, the legacy flag does not matter.
        for allow_legacy_script_hash in [false, true] {
            let db = DBStore::open(tempdir.path(), 64, false, 6, allow_legacy_script_hash).unwrap();
            assert_eq!(db.script_hasher, hasher);
            assert_eq!(db.hash(b"test"), hash);
        }

        // Another database gets another key, even with the legacy flag.
        let other_dir = tempfile::TempDir::new().unwrap();
        let other = DBStore::open(other_dir.path(), 64, false, 6, true).unwrap();
        assert!(matches!(other.script_hasher, ScriptHasher::KeyedSip { .. }));
        assert_ne!(other.hash(b"test"), hash);
    }

    #[test]
    fn keyed_database_not_opened_by_previous_binaries() {
        let tempdir = tempfile::TempDir::new().unwrap();
        drop(DBStore::open(tempdir.path(), 64, false, 6, false).unwrap());

        // Previous binaries open the database with these column families only.
        let mut opts = rocksdb::Options::default();
        opts.create_missing_column_families(true);
        let err = DB::open_cf(&opts, tempdir.path(), COLUMN_FAMILIES).unwrap_err();
        assert!(err.to_string().contains(META_CF), "{err}");
    }

    #[test]
    fn legacy_database_needs_flag() {
        let tempdir = tempfile::TempDir::new().unwrap();
        create_legacy_database(tempdir.path(), 42);

        let err = DBStore::open(tempdir.path(), 64, false, 6, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("--allow-legacy-script-hash"),
            "{err:#}"
        );

        // With the flag it opens with its salt, unchanged.
        let db = DBStore::open(tempdir.path(), 64, false, 6, true).unwrap();
        assert_eq!(db.script_hasher, ScriptHasher::SaltedFx(42));
        drop(db);
        // And it is still readable by previous binaries.
        assert!(!column_families(tempdir.path()).contains(&META_CF.to_string()));
    }

    #[test]
    fn test_db() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path(), 64, true, 6, false).unwrap();

        let format_version = read_format_version(&db.db).unwrap();
        assert_eq!(format_version, 2);
        let hasher = get_or_init_script_hasher(&db.db, format_version, false).unwrap();
        assert!(matches!(hasher, ScriptHasher::KeyedSip { .. }));
        assert_eq!(hasher, db.script_hasher);

        let o = OutPoint::null();
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

        let txid = crate::be::Txid::all_zeros();

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
    fn test_reorg_data_written_only_after_ibd_finished() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path(), 64, false, 6, false).unwrap();
        let reorg_cf = db.db.cf_handle(REORG_CF).unwrap();
        let txid = crate::be::Txid::all_zeros();

        let block = |height: u32| BlockMeta::new(height, BlockHash::all_zeros(), height);
        let created = |vout: u32| {
            let mut m = BTreeMap::new();
            m.insert(OutPoint::new(txid, vout), 1u64);
            m
        };

        // While in IBD the block is indexed but no reorg data is persisted...
        db.update(&block(1), vec![], BTreeMap::new(), created(1))
            .unwrap();
        assert!(db
            .db
            .get_cf(&reorg_cf, 1u32.to_be_bytes())
            .unwrap()
            .is_none());
        // ...so that block can never be rolled back.
        let err = db._reorg(1).unwrap_err().to_string();
        assert!(err.contains("No reorg data found for height 1"), "{err}");

        // Once IBD is finished every indexed block gets reorg data.
        db.ibd_finished();
        db.update(&block(2), vec![], BTreeMap::new(), created(2))
            .unwrap();
        assert!(db
            .db
            .get_cf(&reorg_cf, 2u32.to_be_bytes())
            .unwrap()
            .is_some());
        assert_eq!(
            db.get_utxos(&[OutPoint::new(txid, 2)]).unwrap(),
            vec![Some(1)]
        );

        // Calling it again is a no-op, and the block can be rolled back.
        db.ibd_finished();
        assert!(!db.ibd.load(Ordering::Relaxed));
        db.reorg(2);
        assert!(db
            .db
            .get_cf(&reorg_cf, 2u32.to_be_bytes())
            .unwrap()
            .is_none());
        assert_eq!(db.get_utxos(&[OutPoint::new(txid, 2)]).unwrap(), vec![None]);
    }

    #[test]
    fn rollback_tip_stays_removed_after_reopen() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let db = DBStore::open(tempdir.path(), 64, false, 6, false).unwrap();
        db.ibd_finished();

        for height in 0..=1 {
            let block = BlockMeta::new(
                height,
                BlockHash::from_byte_array([height as u8; 32]),
                height,
            );
            db.update(&block, vec![], BTreeMap::new(), BTreeMap::new())
                .unwrap();
        }
        assert_eq!(db.iter_hash_ts().last().unwrap().height(), 1);

        db.reorg(1);
        drop(db);

        // Restart before a replacement block has been indexed.
        let db = DBStore::open(tempdir.path(), 64, false, 6, false).unwrap();
        let blocks: Vec<_> = db.iter_hash_ts().collect();
        assert_eq!(blocks.last().unwrap().height(), 0);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].hash(), BlockHash::all_zeros());
        assert_eq!(blocks[0].timestamp(), 0);

        // The preceding block's undo row must still allow a deeper rollback.
        db.reorg(0);
        assert!(db.iter_hash_ts().next().is_none());
    }

    #[test]
    fn test_static_txseen_round_trip() {
        let txseen = TxSeen::new(crate::be::Txid::all_zeros(), 0, V::Undefined);
        let txs = vec![txseen.clone()];
        let serialized = vec_tx_seen_to_be_bytes(&txs);
        assert_eq!(serialized.len(), 34);
        let deserialized = vec_tx_seen_from_be_bytes(&serialized).unwrap();
        assert_eq!(txs, deserialized);

        let mut txseen = TxSeen::new(crate::be::Txid::all_zeros(), 0, V::Undefined);
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

        let txseen = TxSeen::new(crate::be::Txid::all_zeros(), 0, V::Vout(1));
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
            outpoints.push(OutPoint::new(txid.into(), vout));
        }

        // Add some specific test cases to ensure edge cases work
        let zero_txid = Txid::all_zeros();
        let max_txid = Txid::from_byte_array([0xff; 32]);
        outpoints.push(OutPoint::new(zero_txid.into(), 0));
        outpoints.push(OutPoint::new(zero_txid.into(), 1));
        outpoints.push(OutPoint::new(zero_txid.into(), u32::MAX));
        outpoints.push(OutPoint::new(max_txid.into(), 0));
        outpoints.push(OutPoint::new(max_txid.into(), u32::MAX));

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
