use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
};

use crate::ScriptHash;

pub type DescIndexHash = u64;

pub struct DerivationCache {
    cache: HashMap<DescIndexHash, ScriptHash>, // TODO use passthrough hasher
}

impl DerivationCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::default(),
        }
    }
    pub fn add(&mut self, x: DescIndexHash, script_pubkey: ScriptHash) {
        // TODO this should delete old entries to avoid growing indefinitely
        self.cache.insert(x, script_pubkey);
    }
    pub fn get(&self, x: DescIndexHash) -> Option<ScriptHash> {
        self.cache.get(&x).cloned()
    }

    pub fn hash(desc: &str, index: u32) -> DescIndexHash {
        let mut hasher = DefaultHasher::default();
        desc.hash(&mut hasher);
        index.hash(&mut hasher);
        hasher.finish()
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }
}
