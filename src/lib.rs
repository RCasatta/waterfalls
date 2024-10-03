use std::hash::Hasher;

use elements::{BlockHash, Txid};
use lazy_static::lazy_static;
use prometheus::{labels, opts, register_counter, register_histogram_vec, Counter, HistogramVec};
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

/// Request to the waterfalls endpoint
pub struct WaterfallRequest {
    descriptor: String,

    /// Requested page, 0 if not specified
    /// The first returned index is equal to `page * 1000`
    /// The same page is used for all the descriptor (ie both external and internal)
    page: u16,
}

/// Response from the waterfalls endpoint
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BlockHash>,

    #[serde(skip_serializing_if = "Option::is_none")]
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

lazy_static! {
    pub(crate) static ref WATERFALLS_COUNTER: Counter = register_counter!(opts!(
        "waterfalls_requests_total",
        "Number of waterfalls requests made.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub(crate) static ref WATERFALLS_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "waterfalls_request_duration_seconds",
        "The waterfalls request latencies in seconds.",
        &["handler"]
    )
    .unwrap();
}

fn hash_str(s: &str) -> u64 {
    let mut hasher = fxhash::FxHasher::default();
    hasher.write(s.as_bytes());
    hasher.finish()
}
