use std::str::FromStr;

use bitcoin::hashes::{sha256d, Hash};
use minicbor::{bytes::ByteArray, Decoder, Encoder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A transaction identifier.
///
/// This type don't discriminate between bitcoin and elements, so that in binary format doesn't occupy more space.
#[derive(Clone, PartialEq, Eq, Debug, Copy, Ord, PartialOrd, Hash)]
pub struct Txid(sha256d::Hash);

impl Txid {
    pub fn bitcoin(self) -> bitcoin::Txid {
        bitcoin::Txid::from_raw_hash(self.0)
    }

    pub fn elements(self) -> elements::Txid {
        elements::Txid::from_raw_hash(self.0)
    }

    pub fn from_raw_hash(hash: sha256d::Hash) -> Self {
        Self(hash)
    }

    pub(crate) fn from_slice(slice: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(Self(sha256d::Hash::from_slice(slice)?))
    }

    pub(crate) fn as_byte_array(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn all_zeros() -> Self {
        Self(sha256d::Hash::from_slice(&[0u8; 32]).unwrap())
    }
}

impl From<elements::Txid> for Txid {
    fn from(txid: elements::Txid) -> Self {
        Self(txid.into())
    }
}

impl From<bitcoin::Txid> for Txid {
    fn from(txid: bitcoin::Txid) -> Self {
        Self(txid.into())
    }
}

impl FromStr for Txid {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Txid(sha256d::Hash::from_str(s)?))
    }
}

impl std::fmt::Display for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<Ctx> minicbor::Encode<Ctx> for Txid {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(self.0.as_ref())?;
        Ok(())
    }
}

impl<'b, Ctx> minicbor::Decode<'b, Ctx> for Txid {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        let bytes = d.decode::<ByteArray<32>>()?;
        Ok(Txid(sha256d::Hash::from_slice(bytes.as_slice()).map_err(
            |_| minicbor::decode::Error::message("invalid 32-byte hash"),
        )?))
    }
}

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            panic!("Non-human readable serialization not implemented for Txid")
        }
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Txid::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            panic!("Non-human readable deserialization not implemented for Txid")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_txid_cbor_roundtrip() {
        let txid_str = "1111111111111111111111111111111111111111111111111111111111111111";
        let txid = Txid::from_str(txid_str).unwrap();

        // Test encoding
        let mut buffer = Vec::new();
        minicbor::encode(&txid, &mut buffer).unwrap();

        // Test decoding
        let decoded_txid: Txid = minicbor::decode(&buffer).unwrap();

        // Verify roundtrip
        assert_eq!(txid.0, decoded_txid.0);

        // Test conversion methods still work
        let _bitcoin_txid = decoded_txid.bitcoin();
        let _elements_txid = txid.elements();
    }

    #[test]
    fn test_txid_cbor_format() {
        let txid_str = "1111111111111111111111111111111111111111111111111111111111111111";
        let txid = Txid::from_str(txid_str).unwrap();

        let mut buffer = Vec::new();
        minicbor::encode(&txid, &mut buffer).unwrap();

        // Should be encoded as bytes (32 bytes + CBOR overhead)
        assert_eq!(buffer.len(), 34); // 1 byte for type + 1 byte for length + 32 bytes for hash

        // First byte should indicate bytes type with length 32
        assert_eq!(buffer[0], 0x58); // Major type 2 (bytes), additional info 24 (1-byte length follows)
        assert_eq!(buffer[1], 32); // Length is 32 bytes
    }

    #[test]
    fn test_txid_string_roundtrip() {
        // Use non-symmetric bytes to catch ordering issues
        let txid_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let txid = Txid::from_str(txid_str).unwrap();

        // Test string roundtrip
        let roundtrip_str = txid.to_string();
        assert_eq!(txid_str, roundtrip_str);

        // Test parsing the roundtrip string
        let roundtrip_txid = Txid::from_str(&roundtrip_str).unwrap();
        assert_eq!(txid.0, roundtrip_txid.0);
    }

    #[test]
    fn test_txid_consistency_with_bitcoin() {
        // Use non-symmetric bytes to catch ordering issues
        let txid_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let our_txid = Txid::from_str(txid_str).unwrap();

        // Create bitcoin txid from the same string
        let bitcoin_txid = bitcoin::Txid::from_str(txid_str).unwrap();

        // Verify our string representation matches bitcoin
        assert_eq!(our_txid.to_string(), bitcoin_txid.to_string());

        // Test conversion - need separate instance since method consumes self
        let our_txid_for_bitcoin = Txid::from_str(txid_str).unwrap();

        // Verify conversion produces the same underlying value
        assert_eq!(our_txid_for_bitcoin.bitcoin(), bitcoin_txid);

        // Verify the converted txid also produces the same string representation
        let converted_bitcoin = Txid::from_str(txid_str).unwrap().bitcoin();
        assert_eq!(converted_bitcoin.to_string(), bitcoin_txid.to_string());

        // Test that elements conversion works (even if string representation differs)
        let our_txid_for_elements = Txid::from_str(txid_str).unwrap();
        let elements_txid = elements::Txid::from_str(txid_str).unwrap();
        assert_eq!(our_txid_for_elements.elements(), elements_txid);
    }

    #[test]
    fn test_txid_serde_json() {
        // Test with a specific txid string
        let txid_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let txid = Txid::from_str(txid_str).unwrap();

        // Test serialization to JSON (human readable)
        let json = serde_json::to_string(&txid).unwrap();
        assert_eq!(json, format!("\"{}\"", txid_str));

        // Test deserialization from JSON (human readable)
        let deserialized_txid: Txid = serde_json::from_str(&json).unwrap();
        assert_eq!(txid.0, deserialized_txid.0);
        assert_eq!(txid.to_string(), deserialized_txid.to_string());
    }
}
