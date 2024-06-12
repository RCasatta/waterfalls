use elements::{BlockHash, Txid};
use serde::{Deserialize, Serialize};

mod fetch;
pub mod server;
mod store;
mod threads;

#[cfg(feature = "test_env")]
pub mod test_env;

type ScriptHash = u64;
type Height = u32;
type Timestamp = u32;

/// Request to the waterfall endpoint
pub struct WaterfallRequest {
    descriptor: String,

    /// Requested page, 0 if not specified
    /// The first returned index is equal to `page * 1000`
    /// The same page is used for all the descriptor (ie both external and internal)
    page: u16,
}

/// Response from the waterfall endpoint
#[derive(Serialize, Deserialize, Debug)]
pub struct WaterfallResponse {
    pub txs_seen: std::collections::BTreeMap<String, Vec<Vec<TxSeen>>>,
    pub page: u16,
}

impl WaterfallResponse {
    pub fn is_empty(&self) -> bool {
        self.txs_seen
            .iter()
            .flat_map(|(_, v)| v.iter())
            .all(|a| a.is_empty())
    }
    pub fn count_non_empty(&self) -> usize {
        self.txs_seen
            .iter()
            .flat_map(|(_, v)| v.iter())
            .filter(|a| !a.is_empty())
            .count()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TxSeen {
    pub txid: Txid,
    pub height: Height,
    pub block_hash: Option<BlockHash>,
    pub block_timestamp: Option<Timestamp>,
}
impl TxSeen {
    pub fn new(txid: Txid, height: Height) -> Self {
        Self {
            txid,
            height,
            block_hash: None,
            block_timestamp: None,
        }
    }

    pub fn mempool(txid: Txid) -> TxSeen {
        TxSeen::new(txid, 0)
    }
}
