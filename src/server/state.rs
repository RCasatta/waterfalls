use std::{
    cmp::Ordering,
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::{
    server::{derivation_cache::DerivationCache, Mempool},
    store::{AnyStore, BlockMeta, Store},
    Timestamp,
};
use age::x25519::Identity;
use bitcoin::{key::Secp256k1, secp256k1::All, PrivateKey};
use elements::BlockHash;
use tokio::sync::{Mutex, RwLock};

use super::{sign::p2pkh, Error};

const DESCRIPTOR_METRICS_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const DESCRIPTOR_METRICS_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

pub struct State {
    /// An asymmetric encryption key, the public key is used to optionally encrypt the descriptor field so that it's harder to leak it.
    pub key: Identity,

    /// The private key of the server address used to sign responses
    pub wif_key: PrivateKey,

    pub store: AnyStore,
    pub mempool: Mutex<Mempool>,
    pub mempool_cache: Mutex<HashMap<crate::be::Txid, crate::be::MempoolTx>>,
    pub blocks_hash_ts: Mutex<Vec<(BlockHash, Timestamp)>>, // TODO should be moved into the Store, but in memory for db

    pub secp: Secp256k1<All>,

    pub max_addresses: usize,
    pub max_txs_seen: usize,

    pub cache_control_seconds: u32,

    pub derivation_cache: Mutex<DerivationCache>,

    pub cached_fee_estimates: RwLock<(HashMap<u16, f64>, Option<Instant>)>,

    descriptor_metrics: Mutex<DescriptorMetrics>,
}

impl State {
    pub fn new(
        store: AnyStore,
        key: Identity,
        wif_key: PrivateKey,
        max_addresses: usize,
        max_txs_seen: usize,
        cache_control_seconds: u32,
        derivation_cache_capacity: usize,
    ) -> Result<Self, Error> {
        Ok(State {
            key,
            wif_key,
            store,
            mempool: Mutex::new(Mempool::new()),
            mempool_cache: Mutex::new(HashMap::new()),
            blocks_hash_ts: Mutex::new(Vec::new()),
            secp: bitcoin::key::Secp256k1::new(),
            max_addresses,
            max_txs_seen,
            cache_control_seconds,
            derivation_cache: Mutex::new(DerivationCache::new(derivation_cache_capacity)),
            cached_fee_estimates: RwLock::new((HashMap::new(), None)),
            descriptor_metrics: Mutex::new(DescriptorMetrics::new()),
        })
    }

    /// The tip of the blockchain, in other words the block with highest height
    /// It must be granted if returned tip is `Some(x)`, `self.block_hash_ts.get(x)` is some.
    pub async fn tip_height(&self) -> Option<u32> {
        (self.blocks_hash_ts.lock().await.len() as u32).checked_sub(1)
    }

    pub async fn tip(&self) -> Option<crate::BlockMeta> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        let height = (blocks_hash_ts.len() as u32).checked_sub(1);
        let hash_timestamp = blocks_hash_ts.last();
        match (hash_timestamp, height) {
            (Some((hash, timestamp)), Some(height)) => Some(crate::BlockMeta {
                h: height,
                b: *hash,
                t: *timestamp,
            }),
            _ => None,
        }
    }

    pub async fn tip_hash(&self) -> Option<BlockHash> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        blocks_hash_ts.last().map(|e| e.0)
    }

    pub async fn tip_timestamp(&self) -> Option<Timestamp> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        blocks_hash_ts.last().map(|e| e.1)
    }

    pub async fn block_hash(&self, height: u32) -> Option<BlockHash> {
        let blocks_hash_ts = self.blocks_hash_ts.lock().await;
        blocks_hash_ts.get(height as usize).map(|e| e.0)
    }
    pub async fn set_hash_ts(&self, meta: &BlockMeta) {
        let mut blocks_hash_ts = self.blocks_hash_ts.lock().await;
        update_hash_ts(&mut blocks_hash_ts, meta);
    }
    /// Roll back `blocks_hash_ts` for a reorged block and invoke `store.reorg`.
    ///
    /// Returns the previous block's metadata so the caller can resume indexing
    /// from there.
    pub(crate) async fn handle_reorg(&self, reorged_height: u32) -> BlockMeta {
        let previous_height = reorged_height - 1;
        let mut blocks_hash_ts = self.blocks_hash_ts.lock().await;
        let (hash, ts) = blocks_hash_ts
            .get(previous_height as usize)
            .cloned()
            .expect("can't get previous block_hash");
        blocks_hash_ts.truncate(reorged_height as usize);
        drop(blocks_hash_ts);
        self.store.reorg(reorged_height);
        BlockMeta::new(previous_height, hash, ts)
    }

    pub fn address(&self) -> bitcoin::Address {
        p2pkh(&self.secp, &self.wif_key)
    }

    pub async fn record_descriptor_access(&self, id: u64) {
        let mut descriptor_metrics = self.descriptor_metrics.lock().await;
        descriptor_metrics.record(id, Instant::now());
        crate::set_unique_descriptors(descriptor_metrics.unique_count());
    }
}

fn update_hash_ts(blocks_hash_ts: &mut Vec<(BlockHash, u32)>, meta: &BlockMeta) {
    match blocks_hash_ts.len().cmp(&(meta.height() as usize)) {
        Ordering::Less => {
            error_panic!(
                "unexpected: height:{} blocks_hash_ts:{}",
                meta.height(),
                blocks_hash_ts.len()
            );
        }
        Ordering::Equal => {
            // Most common case of adding a new block
            blocks_hash_ts.push((meta.hash(), meta.timestamp()))
        }
        Ordering::Greater => {
            // We are reorging
            blocks_hash_ts.get_mut(meta.height() as usize).map(|e| {
                e.0 = meta.hash();
                e.1 = meta.timestamp();
            });
            blocks_hash_ts.truncate(meta.height() as usize + 1); // if the reorg is longer than one block, we need to truncate the vector
        }
    }

    assert_eq!(blocks_hash_ts.len() as u32 - 1, meta.height());
}

struct DescriptorMetrics {
    last_seen: HashMap<u64, Instant>,
    last_prune: Instant,
}

impl DescriptorMetrics {
    fn new() -> Self {
        Self {
            last_seen: HashMap::new(),
            last_prune: Instant::now(),
        }
    }

    fn record(&mut self, id: u64, now: Instant) {
        self.last_seen.insert(id, now);
        if now.duration_since(self.last_prune) >= DESCRIPTOR_METRICS_PRUNE_INTERVAL {
            self.prune(now);
            self.last_prune = now;
        }
    }

    fn prune(&mut self, now: Instant) {
        self.last_seen
            .retain(|_, last_seen| now.duration_since(*last_seen) <= DESCRIPTOR_METRICS_RETENTION);
    }

    fn unique_count(&self) -> usize {
        self.last_seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_update_vec() {
        let mut blocks_hash_ts = vec![(
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            0,
        )];

        // Test adding a new block (height 1)
        let meta = BlockMeta::new(
            1,
            BlockHash::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
            100,
        );
        update_hash_ts(&mut blocks_hash_ts, &meta);
        assert_eq!(blocks_hash_ts.len(), 2);
        assert_eq!(blocks_hash_ts[1].0, meta.hash());
        assert_eq!(blocks_hash_ts[1].1, meta.timestamp());

        // Test reorg a block (height 1)
        let meta2 = BlockMeta::new(
            1,
            BlockHash::from_str("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap(),
            101,
        );
        update_hash_ts(&mut blocks_hash_ts, &meta2);
        assert_eq!(blocks_hash_ts.len(), 2);
        assert_eq!(blocks_hash_ts[1].0, meta2.hash());
        assert_eq!(blocks_hash_ts[1].1, meta2.timestamp());

        // Test adding a new block (height 2)
        let meta3 = BlockMeta::new(
            2,
            BlockHash::from_str("3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap(),
            102,
        );
        update_hash_ts(&mut blocks_hash_ts, &meta3);
        assert_eq!(blocks_hash_ts.len(), 3);
        assert_eq!(blocks_hash_ts[2].0, meta3.hash());
        assert_eq!(blocks_hash_ts[2].1, meta3.timestamp());

        // Test double reorg a block (height 1)
        let meta2 = BlockMeta::new(
            1,
            BlockHash::from_str("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap(),
            101,
        );
        update_hash_ts(&mut blocks_hash_ts, &meta2);
        assert_eq!(blocks_hash_ts.len(), 2);
        assert_eq!(blocks_hash_ts[1].0, meta2.hash());
        assert_eq!(blocks_hash_ts[1].1, meta2.timestamp());
    }

    #[test]
    fn test_descriptor_metrics_record_and_prune() {
        let base = Instant::now();
        let mut metrics = DescriptorMetrics {
            last_seen: HashMap::new(),
            last_prune: base,
        };

        metrics.record(1, base);
        assert_eq!(metrics.unique_count(), 1);

        metrics.record(1, base + Duration::from_secs(1));
        assert_eq!(metrics.unique_count(), 1);

        metrics.record(2, base + Duration::from_secs(2));
        assert_eq!(metrics.unique_count(), 2);

        assert_eq!(metrics.unique_count(), 2);

        metrics.record(
            3,
            base + DESCRIPTOR_METRICS_RETENTION + DESCRIPTOR_METRICS_PRUNE_INTERVAL,
        );
        assert_eq!(metrics.unique_count(), 1);
    }

    #[tokio::test]
    async fn test_reorg_truncates_blocks_hash_ts() {
        use crate::store::memory::MemoryStore;
        use bitcoin::NetworkKind;
        use std::collections::BTreeMap;

        let store = AnyStore::Mem(MemoryStore::new());
        let key = Identity::generate();
        let wif_key = PrivateKey::generate(NetworkKind::Test);
        let state = State::new(store, key, wif_key, 100, 100, 5, 1000).unwrap();

        let hash_0 =
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let hash_1 =
            BlockHash::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let hash_2 =
            BlockHash::from_str("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();

        let meta_0 = BlockMeta::new(0, hash_0, 100);
        let meta_1 = BlockMeta::new(1, hash_1, 200);
        let meta_2 = BlockMeta::new(2, hash_2, 300);

        // Index 3 blocks in both the store and blocks_hash_ts
        for meta in [&meta_0, &meta_1, &meta_2] {
            state.set_hash_ts(meta).await;
            state
                .store
                .update(meta, vec![], BTreeMap::new(), BTreeMap::new())
                .unwrap();
        }
        assert_eq!(state.tip_height().await, Some(2));
        assert_eq!(state.tip_hash().await, Some(hash_2));

        // Reorg height 2: store and blocks_hash_ts must both roll back
        let prev = state.handle_reorg(2).await;
        assert_eq!(prev.height, 1);
        assert_eq!(prev.hash, hash_1);

        // blocks_hash_ts no longer contains the reorged block
        assert_eq!(state.tip_height().await, Some(1));
        assert_eq!(state.tip_hash().await, Some(hash_1));
        assert_eq!(state.block_hash(2).await, None);
    }
}
