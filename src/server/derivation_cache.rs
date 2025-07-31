use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};

use fxhash::FxHasher;

use crate::ScriptHash;

pub type DescIndexHash = u64;

pub struct DerivationCache {
    cache: HashMap<DescIndexHash, ScriptHash>,
}

impl DerivationCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::default(),
        }
    }
    pub fn add(&mut self, x: DescIndexHash, script_pubkey: ScriptHash) {
        self.cache.insert(x, script_pubkey);
    }
    pub fn get(&self, x: DescIndexHash) -> Option<ScriptHash> {
        self.cache.get(&x).cloned()
    }

    pub fn hash(desc: &str, index: u32) -> DescIndexHash {
        let mut hasher = FxHasher::default();
        desc.hash(&mut hasher);
        index.hash(&mut hasher);
        hasher.finish()
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }
}
