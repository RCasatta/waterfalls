use crate::{
    server::{derivation_cache::DerivationCache, Mempool},
    store::{AnyStore, BlockMeta},
    Timestamp,
};
use age::x25519::Identity;
use bitcoin::{key::Secp256k1, secp256k1::All, PrivateKey};
use elements::BlockHash;
use tokio::sync::Mutex;

use super::{sign::p2pkh, Error};

pub struct State {
    /// An asymmetric encryption key, the public key is used to optionally encrypt the descriptor field so that it's harder to leak it.
    pub key: Identity,

    /// The private key of the server address used to sign responses
    pub wif_key: PrivateKey,

    pub store: AnyStore,
    pub mempool: Mutex<Mempool>,
    pub blocks_hash_ts: Mutex<Vec<(BlockHash, Timestamp)>>, // TODO should be moved into the Store, but in memory for db

    pub secp: Secp256k1<All>,

    pub max_addresses: usize,

    pub derivation_cache: Mutex<DerivationCache>,
}

impl State {
    pub fn new(
        store: AnyStore,
        key: Identity,
        wif_key: PrivateKey,
        max_addresses: usize,
    ) -> Result<Self, Error> {
        Ok(State {
            key,
            wif_key,
            store,
            mempool: Mutex::new(Mempool::new()),
            blocks_hash_ts: Mutex::new(Vec::new()),
            secp: bitcoin::key::Secp256k1::new(),
            max_addresses,
            derivation_cache: Mutex::new(DerivationCache::new(1_000_000)),
        })
    }

    /// The tip of the blockchain, in other words the block with highest height
    /// It must be granted if returned tip is `Some(x)`, `self.block_hash_ts.get(x)` is some.
    pub async fn tip(&self) -> Option<u32> {
        (self.blocks_hash_ts.lock().await.len() as u32).checked_sub(1)
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
        {
            let mut blocks_hash_ts = self.blocks_hash_ts.lock().await;
            blocks_hash_ts.push((meta.hash(), meta.timestamp()));
            assert_eq!(blocks_hash_ts.len() as u32 - 1, meta.height())
        }
    }
    pub fn address(&self) -> bitcoin::Address {
        p2pkh(&self.secp, &self.wif_key)
    }
}
