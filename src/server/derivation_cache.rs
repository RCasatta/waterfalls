use std::hash::{BuildHasher, DefaultHasher, Hash, Hasher};

use lrumap::LruHashMap;

use crate::{cache_counter, ScriptHash};

pub type DescIndexHash = u64;

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
    pub fn new() -> Self {
        Self {
            cache: LruHashMap::with_hasher(1_000_000, PassthroughHasher(0)), // TODO make this configurable
        }
    }
    pub fn add(&mut self, x: DescIndexHash, script_pubkey: ScriptHash) {
        // TODO this should delete old entries to avoid growing indefinitely
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
