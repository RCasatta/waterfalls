use std::{
    cmp::Ordering,
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::{
    server::{derivation_cache::DerivationCache, Mempool},
    store::{AnyStore, BlockMeta},
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
    pub mempool_cache: Mutex<HashMap<crate::be::Txid, crate::be::Transaction>>,
    pub blocks_hash_ts: Mutex<Vec<(BlockHash, Timestamp)>>, // TODO should be moved into the Store, but in memory for db

    pub secp: Secp256k1<All>,

    pub max_addresses: usize,

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
}
