use std::{
    collections::{BTreeMap, BTreeSet},
    hash::Hasher,
};

use crate::cbor::cbor_block_hash;
use elements::{BlockHash, Txid};
use lazy_static::lazy_static;
use minicbor::{Decode, Encode};
use prometheus::{labels, opts, register_counter, register_histogram_vec, Counter, HistogramVec};
use serde::{Deserialize, Serialize};

mod cbor;
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
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct WaterfallResponse {
    pub txs_seen: BTreeMap<String, Vec<Vec<TxSeen>>>,
    pub page: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<BlockHash>,
}

/// Response from the waterfalls endpoint
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct WaterfallResponseV3 {
    pub txs_seen: BTreeMap<String, Vec<Vec<TxRef>>>,
    pub page: u16,
    pub tip: BlockHash,
    pub txids: Vec<Txid>,
    pub blocks_meta: Vec<BlockMeta>,
}

/// The first element is the transaction reference index, the second is the block reference index
type TxRef = [usize; 2];

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Ord, PartialOrd, Encode, Decode)]
pub struct BlockMeta {
    /// The block hash. It's not a `BlockHash` to support CBOR encoding
    #[cbor(n(0), with = "cbor_block_hash")]
    pub b: BlockHash,
    #[cbor(n(1))]
    pub t: Timestamp,
    #[cbor(n(2))]
    pub h: Height,
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

impl TryFrom<WaterfallResponse> for WaterfallResponseV3 {
    type Error = ();

    fn try_from(value: WaterfallResponse) -> Result<Self, Self::Error> {
        let txids: BTreeSet<Txid> = value
            .txs_seen
            .iter()
            .flat_map(|(_, v)| v.iter())
            .flat_map(|a| a.iter())
            .map(|a| a.txid)
            .collect();
        let block_meta: BTreeSet<BlockMeta> = value
            .txs_seen
            .iter()
            .flat_map(|(_, v)| v.iter())
            .flat_map(|a| a.iter())
            .map(|a| {
                Ok::<BlockMeta, ()>(BlockMeta {
                    b: a.block_hash.ok_or(())?,
                    t: a.block_timestamp.ok_or(())?,
                    h: a.height,
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut txs_seen = BTreeMap::new();
        for (d, v) in value.txs_seen.iter() {
            let mut txs_seen_d = vec![];
            for a in v.iter() {
                let mut current_script = vec![];
                for b in a.iter() {
                    // TODO I used BTreeSet thinking you can binary search on it,
                    // but it doesn't seem possible, maybe sorted and unique vec then?
                    let t = txids
                        .iter()
                        .position(|a| a == &b.txid)
                        .expect("by construction");
                    let b = block_meta
                        .iter()
                        .position(|a| a.b == b.block_hash.expect("would have errored before"))
                        .expect("by construction");
                    current_script.push([t, b]);
                }
                txs_seen_d.push(current_script);
            }
            txs_seen.insert(d.clone(), txs_seen_d);
        }
        let r = WaterfallResponseV3 {
            txs_seen,
            page: value.page,
            tip: value.tip.ok_or(())?,
            txids: txids.into_iter().collect(),
            blocks_meta: block_meta.into_iter().collect(),
        };
        Ok(r)
    }
}

impl From<WaterfallResponseV3> for WaterfallResponse {
    fn from(value: WaterfallResponseV3) -> Self {
        let mut txs_seen = BTreeMap::new();
        for (d, v) in value.txs_seen.iter() {
            let mut txs_seen_d = vec![];
            for a in v.iter() {
                let mut current_script = vec![];
                for b in a.iter() {
                    current_script.push(TxSeen {
                        txid: value.txids[b[0]],
                        height: value.blocks_meta[b[1]].h as u32,
                        block_hash: Some(value.blocks_meta[b[1]].b),
                        block_timestamp: Some(value.blocks_meta[b[1]].t),
                    });
                }
                txs_seen_d.push(current_script);
            }
            txs_seen.insert(d.clone(), txs_seen_d);
        }
        let r = WaterfallResponse {
            txs_seen,
            page: value.page,
            tip: Some(value.tip),
        };
        r
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waterfall_response_v3_v2_roundtrip() {
        let s = include_str!("../tests/data/waterfall_response_v2.json");
        assert_eq!(s.len(), 8065);
        let v2: WaterfallResponse = serde_json::from_str(&s).unwrap();

        let v3: WaterfallResponseV3 = v2.clone().try_into().unwrap();
        let s = serde_json::to_string(&v3).unwrap();
        println!("{}", s);
        assert_eq!(s.len(), 3028);
        let v2_back: WaterfallResponse = v3.into();
        assert_eq!(v2, v2_back);
    }
}
