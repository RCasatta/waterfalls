use std::hash::{DefaultHasher, Hash, Hasher};

use lrumap::LruHashMap;

use crate::{cache_counter, ScriptHash};

pub type DescIndexHash = u64;

pub struct DerivationCache {
    cache: LruHashMap<DescIndexHash, ScriptHash>, // TODO use passthrough hasher
}

impl DerivationCache {
    pub fn new() -> Self {
        Self {
            cache: LruHashMap::new(1_000_000), // TODO make this configurable
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
