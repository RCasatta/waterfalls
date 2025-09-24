use std::collections::BTreeMap;

use crate::cbor::{cbor_block_hash, cbor_opt_block_hash};
pub use be::Family;
use elements::{BlockHash, OutPoint};
use lazy_static::lazy_static;
use minicbor::{Decode, Encode};
use prometheus::{
    labels, opts, register_counter, register_histogram_vec, register_int_counter_vec,
    register_int_gauge, Counter, HistogramVec, IntCounterVec, IntGauge,
};
use serde::{Deserialize, Serialize};

/// Macro that logs an error and panics with the same message.
/// This is useful because error logs are more easily seen in systemd logs.
macro_rules! error_panic {
    ($($arg:tt)*) => {
        {
            let msg = format!($($arg)*);
            log::error!("{}", msg);
            panic!("{}", msg);
        }
    };
}

pub(crate) use error_panic;

pub mod be;
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
    descriptor: be::Descriptor,

    /// Requested page, 0 if not specified
    /// The first returned index is equal to `page * 10000`
    /// The same page is used for all the descriptor (ie both external and internal)
    page: u16,

    /// The last known derivation index to scan up to, 0 if not specified
    /// This can be used to override the GAP_LIMIT
    to_index: u32,

    /// If true, does not return txid of transactions having only spent outputs
    utxo_only: bool,
}

/// Request to the waterfalls endpoint using a list of addresses
#[derive(Debug)]
pub struct AddressesRequest {
    addresses: Vec<be::Address>,

    /// Requested page, 0 if not specified
    /// The first returned index is equal to `page * 10000`
    page: u16,

    utxo_only: bool,
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

    #[cbor(n(3))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip_meta: Option<BlockMeta>,
}

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

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum V {
    #[default]
    Undefined,
    Vin(u32),
    Vout(u32),
}

impl Serialize for V {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i32(self.raw())
    }
}

impl<'de> Deserialize<'de> for V {
    fn deserialize<D>(deserializer: D) -> Result<V, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = i32::deserialize(deserializer)?;
        Ok(V::from_raw(raw))
    }
}

impl<Ctx> Encode<Ctx> for V {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.i32(self.raw())?;
        Ok(())
    }
}

impl<'b, Ctx> Decode<'b, Ctx> for V {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<Self, minicbor::decode::Error> {
        let inner = d.i32()?;
        Ok(V::from_raw(inner))
    }
}

impl V {
    /// Creates a V from a raw i32 value (for deserialization)
    pub fn from_raw(raw: i32) -> Self {
        match raw {
            0 => V::Undefined,
            i if i > 0 => V::Vout((i - 1) as u32),
            i => V::Vin((-i - 1) as u32),
        }
    }

    /// Returns the vout index if this V represents an output
    pub fn vout(&self) -> Option<u32> {
        match self {
            V::Vout(index) => Some(*index),
            _ => None,
        }
    }

    /// Returns the vin index if this V represents an input
    pub fn vin(&self) -> Option<u32> {
        match self {
            V::Vin(index) => Some(*index),
            _ => None,
        }
    }

    /// Returns true if this V is undefined (value is 0)
    pub fn is_undefined(&self) -> bool {
        matches!(self, V::Undefined)
    }

    /// Returns the raw inner value
    pub fn raw(&self) -> i32 {
        match self {
            V::Undefined => 0,
            V::Vin(index) => -((index + 1) as i32),
            V::Vout(index) => (index + 1) as i32,
        }
    }
}

impl From<i32> for V {
    fn from(v: i32) -> Self {
        Self::from_raw(v)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub struct TxSeen {
    #[cbor(n(0))]
    pub txid: crate::be::Txid,

    #[cbor(n(1))]
    pub height: Height,

    /// The block hash of block containing the transaction where the script was seen.
    ///
    /// The cbor index should be at the end because if you have a following field and this is None,
    /// it is serialized as 32 zeros, if it's in the end instead the lower number of the array elements
    /// make it guess is None without actually serializing it
    #[cbor(n(2), with = "cbor_opt_block_hash")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BlockHash>,

    #[cbor(n(3))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_timestamp: Option<Timestamp>,

    /// Vout or Vin depending on wether this script is:
    /// - Not defined when 0
    /// - the script_pubkey in the (v-1) vout output of this transaction
    /// - the script_pubkey of the previous output of the vin (-v-1) input of this transaction
    #[cbor(n(4))]
    #[serde(skip_serializing_if = "V::is_undefined", default)]
    pub v: V,
}

impl TxSeen {
    pub fn new(txid: crate::be::Txid, height: Height, v: V) -> Self {
        Self {
            txid,
            height,
            block_hash: None,
            block_timestamp: None,
            v,
        }
    }

    pub fn mempool(txid: crate::be::Txid, v: V) -> TxSeen {
        TxSeen::new(txid, 0, v)
    }

    pub fn outpoint(&self) -> Option<OutPoint> {
        self.v
            .vout()
            .map(|vout| OutPoint::new(self.txid.elements(), vout))
    }
}

lazy_static! {
    pub(crate) static ref WATERFALLS_COUNTER: Counter = register_counter!(opts!(
        "waterfalls_requests_total",
        "Number of waterfalls requests made.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub(crate) static ref BLOCKCHAIN_TIP: IntGauge =
        register_int_gauge!(opts!("blockchain_tip", "Blockchain tip height.")).unwrap();
    static ref MEMPOOL_LOOP_DURATION: IntGauge = register_int_gauge!(
        "waterfalls_mempool_loop_duration_milliseconds",
        "The duration of each loop iteration computing the mempool in milliseconds.",
    )
    .unwrap();
    static ref MEMPOOL_TXS_COUNT: IntGauge = register_int_gauge!(opts!(
        "waterfalls_mempool_txs_count",
        "The number of transactions in the mempool."
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
    static ref WATERFALLS_CACHE_COUNTER: IntCounterVec = register_int_counter_vec!(
        "waterfalls_cache_counter",
        "Hit/Miss of Waterfalls caches",
        &["name", "event"]
    )
    .unwrap();
}

pub(crate) fn cache_counter(cache_name: &str, hit_miss: bool) {
    let hit_miss = if hit_miss { "hit" } else { "miss" };
    crate::WATERFALLS_CACHE_COUNTER
        .with_label_values(&[cache_name, hit_miss])
        .inc();
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::hex::DisplayHex;
    use prefix_uvarint::PrefixVarInt;

    use super::*;

    #[test]
    fn test_prefix_uvarint() {
        let mut value_buf = [0u8; prefix_uvarint::MAX_LEN];
        assert_eq!(1u32.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(10u32.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(63u32.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(64u32.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(100u32.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(127u32.encode_prefix_varint(&mut value_buf), 1);
        assert_eq!(128u32.encode_prefix_varint(&mut value_buf), 2);
        assert_eq!(1000u32.encode_prefix_varint(&mut value_buf), 2);
        assert_eq!(10000u32.encode_prefix_varint(&mut value_buf), 2);
        assert_eq!(100000u32.encode_prefix_varint(&mut value_buf), 3);
        assert_eq!(1000000u32.encode_prefix_varint(&mut value_buf), 3);
        assert_eq!(3_449_626u32.encode_prefix_varint(&mut value_buf), 4);
        assert_eq!(33_449_626u32.encode_prefix_varint(&mut value_buf), 4);
    }

    #[test]
    fn test_prefix_uvarint_concat() {
        let mut vec = vec![0u8; 32];
        let len1 = 1u32.encode_prefix_varint(&mut vec[..]);
        assert_eq!(len1, 1);
        let len2 = 10u32.encode_prefix_varint(&mut vec[len1..]);
        assert_eq!(len2, 1);
        let len3 = 100u32.encode_prefix_varint(&mut vec[len1 + len2..]);
        assert_eq!(len3, 1);

        let (height, len1) = u32::decode_prefix_varint(&vec[..]).unwrap();
        assert_eq!(height, 1);
        assert_eq!(len1, 1);
        let (height, len2) = u32::decode_prefix_varint(&vec[len1..]).unwrap();
        assert_eq!(height, 10);
        assert_eq!(len2, 1);
        let (height, len3) = u32::decode_prefix_varint(&vec[len1 + len2..]).unwrap();
        assert_eq!(height, 100);
        assert_eq!(len3, 1);
    }

    #[test]
    fn test_cbor_txseen() {
        let txid = crate::be::Txid::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let txseen = TxSeen::new(txid, 3_000_001, V::Undefined); // Was 0, meaning undefined
        let cbor = minicbor::to_vec(&txseen).unwrap();

        // TODO current cbor serialization is bad cause it's serializing v and thus also Blockhash
        // should be 82582011111111111111111111111111111111111111111111111111111111111111111a002dc6c1
        assert_eq!(
            cbor.to_lower_hex_string(),
            "85582011111111111111111111111111111111111111111111111111111111111111111a002dc6c158200000000000000000000000000000000000000000000000000000000000000000f600"
        );
        /*
        82                                      # array(2)
           58 20                                # bytes(32)
              1111111111111111111111111111111111111111111111111111111111111111 # "\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"
           1A 002DC6C1                          # unsigned(3000001)
        */

        assert_eq!(cbor.len(), 76);
    }
}
