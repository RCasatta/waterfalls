use std::hash::{BuildHasher, DefaultHasher, Hash, Hasher};

use lrumap::LruHashMap;

use crate::{cache_counter, ScriptHash};

pub type DescIndexHash = u64;

/// A cache mapping (descriptor/derivation indices) -> script hashes.
///
/// This is used to avoid re-calculating the same script hashes for the same descriptor/derivation indices.
///
/// The cache is a LRU cache to hard cap the memory usage.
///
/// The cache use a PassthroughHasher because the key is already a hash.
pub struct DerivationCache {
    cache: LruHashMap<DescIndexHash, ScriptHash, PassthroughHasher>,
}

#[derive(Default)]
struct PassthroughHasher(u64);

impl BuildHasher for PassthroughHasher {
    type Hasher = PassthroughHasher;

    fn build_hasher(&self) -> Self::Hasher {
        PassthroughHasher(0)
    }
}

impl Hasher for PassthroughHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, _bytes: &[u8]) {
        panic!("passtrough hasher should not pass here!")
    }

    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }
}

impl DerivationCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: LruHashMap::with_hasher(capacity, PassthroughHasher(0)),
        }
    }
    pub fn add(&mut self, x: DescIndexHash, script_pubkey: ScriptHash) {
        self.cache.push(x, script_pubkey);
    }
    pub fn get(&mut self, x: DescIndexHash) -> Option<ScriptHash> {
        let val = self.cache.get(&x).cloned();
        let hit_miss = val.is_some();
        cache_counter("derivation_cache", hit_miss);
        val
    }

    pub fn hash(desc: &str, index: u32) -> DescIndexHash {
        let mut hasher = DefaultHasher::default();
        desc.hash(&mut hasher);
        index.hash(&mut hasher);
        hasher.finish()
    }
}
