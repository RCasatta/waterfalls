use std::collections::BTreeMap;

use crate::cbor::{cbor_block_hash, cbor_opt_block_hash, cbor_txid, cbor_txids};
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
#[derive(Debug)]
pub enum WaterfallRequest {
    Descriptor(DescriptorRequest),
    Addresses(AddressesRequest),
}

/// Request to the waterfalls endpoint using a descriptor
#[derive(Debug)]
pub struct DescriptorRequest {
    descriptor:
        elements_miniscript::descriptor::Descriptor<elements_miniscript::DescriptorPublicKey>,

    /// Requested page, 0 if not specified
    /// The first returned index is equal to `page * 10000`
    /// The same page is used for all the descriptor (ie both external and internal)
    page: u16,

    /// The last known derivation index to scan up to, 0 if not specified
    /// This can be used to override the GAP_LIMIT
    to_index: u32,
}

/// Request to the waterfalls endpoint using a list of addresses
#[derive(Debug)]
pub struct AddressesRequest {
    addresses: Vec<elements::Address>,

    /// Requested page, 0 if not specified
    /// The first returned index is equal to `page * 10000`
    page: u16,
}

/// Response from the waterfalls endpoint
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct WaterfallResponse {
    #[cbor(n(0))]
    pub txs_seen: BTreeMap<String, Vec<Vec<TxSeen>>>,
    #[cbor(n(1))]
    pub page: u16,

    #[cbor(n(2), with = "cbor_opt_block_hash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<BlockHash>,
}

/// Response from the waterfalls endpoint
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct WaterfallResponseV3 {
    #[cbor(n(0))]
    pub txs_seen: BTreeMap<String, Vec<Vec<TxRef>>>,
    #[cbor(n(1))]
    pub page: u16,
    #[cbor(n(2), with = "cbor_block_hash")]
    pub tip: BlockHash,
    #[cbor(n(3), with = "cbor_txids")]
    pub txids: Vec<Txid>,
    #[cbor(n(4))]
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

impl WaterfallRequest {
    pub fn descriptor(&self) -> Option<&DescriptorRequest> {
        match self {
            WaterfallRequest::Descriptor(d) => Some(d),
            _ => None,
        }
    }

    pub fn addresses(&self) -> Option<&AddressesRequest> {
        match self {
            WaterfallRequest::Addresses(a) => Some(a),
            _ => None,
        }
    }

    pub fn page(&self) -> u16 {
        match self {
            WaterfallRequest::Descriptor(d) => d.page,
            WaterfallRequest::Addresses(a) => a.page,
        }
    }
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
    pub fn count_scripts(&self) -> usize {
        self.txs_seen.iter().flat_map(|(_, v)| v.iter()).count()
    }
}

impl WaterfallResponseV3 {
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
    pub fn count_scripts(&self) -> usize {
        self.txs_seen.iter().flat_map(|(_, v)| v.iter()).count()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub struct TxSeen {
    #[cbor(n(0), with = "cbor_txid")]
    pub txid: Txid,
    #[cbor(n(1))]
    pub height: Height,

    #[cbor(n(2), with = "cbor_opt_block_hash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BlockHash>,

    #[cbor(n(3))]
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
        let mut txids: Vec<Txid> = value
            .txs_seen
            .iter()
            .flat_map(|(_, v)| v.iter())
            .flat_map(|a| a.iter())
            .map(|a| a.txid)
            .collect();
        txids.sort();
        txids.dedup();

        let mut blocks_meta: Vec<BlockMeta> = value
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
            .collect::<Result<Vec<_>, _>>()?;
        blocks_meta.sort();
        blocks_meta.dedup();

        let mut txs_seen = BTreeMap::new();
        for (d, v) in value.txs_seen.iter() {
            let mut txs_seen_d = vec![];
            for a in v.iter() {
                let mut current_script = vec![];
                for b in a.iter() {
                    let t = txids.binary_search(&b.txid).expect("by construction");
                    let b = blocks_meta
                        .binary_search_by_key(
                            &b.block_hash.expect("would have errored before"),
                            |e| e.b,
                        )
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
            txids,
            blocks_meta,
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
                        height: value.blocks_meta[b[1]].h,
                        block_hash: Some(value.blocks_meta[b[1]].b),
                        block_timestamp: Some(value.blocks_meta[b[1]].t),
                    });
                }
                txs_seen_d.push(current_script);
            }
            txs_seen.insert(d.clone(), txs_seen_d);
        }

        WaterfallResponse {
            txs_seen,
            page: value.page,
            tip: Some(value.tip),
        }
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
    pub(crate) static ref WATERFALLS_DB_HISTORY_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "waterfalls_request_db_history_duration_seconds",
        "The waterfalls request db history latencies in seconds.",
        &["handler"]
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::hex::DisplayHex;
    use prefix_uvarint::PrefixVarInt;

    use super::*;

    #[test]
    fn test_waterfall_response_v3_v2_roundtrip() {
        let s = include_str!("../tests/data/waterfall_response_v2.json");
        assert_eq!(s.len(), 8065);
        let v2: WaterfallResponse = serde_json::from_str(&s).unwrap();

        let v3: WaterfallResponseV3 = v2.clone().try_into().unwrap();
        let s = serde_json::to_string(&v3).unwrap();
        assert_eq!(s.len(), 3028);
        let v2_back: WaterfallResponse = v3.into();
        assert_eq!(v2, v2_back);
    }

    #[test]
    fn test_prefix_uvarint() {
        let mut value_buf = [0u8; prefix_uvarint::MAX_LEN];
        assert_eq!(1.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(10.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(63.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(64.encode_prefix_varint(&mut value_buf), 2);
        assert_eq!(100.encode_prefix_varint(&mut value_buf), 2);
        assert_eq!(1000.encode_prefix_varint(&mut value_buf), 2);
        assert_eq!(10000.encode_prefix_varint(&mut value_buf), 3);
        assert_eq!(100000.encode_prefix_varint(&mut value_buf), 3);
        assert_eq!(1000000.encode_prefix_varint(&mut value_buf), 3);
        assert_eq!(3_449_626.encode_prefix_varint(&mut value_buf), 4);
        assert_eq!(33_449_626.encode_prefix_varint(&mut value_buf), 4);
    }

    #[test]
    fn test_cbor_txseen() {
        let txid =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let txseen = TxSeen::new(txid, 3_000_001);
        let cbor = minicbor::to_vec(&txseen).unwrap();
        assert_eq!(
            cbor.to_lower_hex_string(),
            "82582000000000000000000000000000000000000000000000000000000000000000001a002dc6c1"
        );
        assert_eq!(cbor.len(), 40);
    }
}
