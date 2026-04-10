use std::str::FromStr;

use crate::be::Txid;

/// A network-agnostic transaction outpoint.
///
/// Binary encoding intentionally matches both bitcoin::OutPoint and elements::OutPoint:
/// 32 bytes of txid in consensus order, followed by 4 bytes of little-endian vout.
#[derive(Clone, PartialEq, Eq, Debug, Copy, Ord, PartialOrd, Hash)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub const SIZE: usize = 36;

    pub const fn new(txid: Txid, vout: u32) -> Self {
        Self { txid, vout }
    }

    pub fn null() -> Self {
        Self::new(Txid::all_zeros(), u32::MAX)
    }
}

impl From<bitcoin::OutPoint> for OutPoint {
    fn from(outpoint: bitcoin::OutPoint) -> Self {
        Self::new(outpoint.txid.into(), outpoint.vout)
    }
}

impl From<elements::OutPoint> for OutPoint {
    fn from(outpoint: elements::OutPoint) -> Self {
        Self::new(outpoint.txid.into(), outpoint.vout)
    }
}

impl FromStr for OutPoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (txid, vout) = s
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Invalid outpoint format"))?;
        let txid = Txid::from_str(txid)?;
        let vout = vout.parse()?;
        Ok(Self::new(txid, vout))
    }
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

impl elements::encode::Encodable for OutPoint {
    fn consensus_encode<W: std::io::Write>(
        &self,
        mut writer: W,
    ) -> Result<usize, elements::encode::Error> {
        elements::WriteExt::emit_slice(&mut writer, self.txid.as_byte_array())?;
        elements::WriteExt::emit_u32(&mut writer, self.vout)?;
        Ok(Self::SIZE)
    }
}

impl elements::encode::Decodable for OutPoint {
    fn consensus_decode<R: std::io::Read>(mut reader: R) -> Result<Self, elements::encode::Error> {
        let mut txid = [0u8; 32];
        reader.read_exact(&mut txid)?;
        let mut vout = [0u8; 4];
        reader.read_exact(&mut vout)?;
        let txid = Txid::from_array(txid);
        let vout = u32::from_le_bytes(vout);
        Ok(Self::new(txid, vout))
    }
}

#[cfg(test)]
impl OutPoint {
    pub fn bitcoin(self) -> bitcoin::OutPoint {
        bitcoin::OutPoint::new(self.txid.bitcoin(), self.vout)
    }

    pub fn elements(self) -> elements::OutPoint {
        elements::OutPoint::new(self.txid.elements(), self.vout)
    }

    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..32].copy_from_slice(self.txid.as_byte_array());
        bytes[32..].copy_from_slice(&self.vout.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        let txid = Txid::from_array(bytes[..32].try_into().expect("slice has exact size"));
        let vout = u32::from_le_bytes(bytes[32..].try_into().expect("slice has exact size"));
        Self::new(txid, vout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{
        deserialize as bitcoin_deserialize, serialize as bitcoin_serialize, WriteExt,
    };
    use elements::encode::{deserialize as elements_deserialize, serialize as elements_serialize};

    impl bitcoin::consensus::Encodable for OutPoint {
        fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
            &self,
            writer: &mut W,
        ) -> Result<usize, bitcoin::io::Error> {
            writer.emit_slice(self.txid.as_byte_array())?;
            writer.emit_u32(self.vout)?;
            Ok(36)
        }
    }

    impl bitcoin::consensus::Decodable for OutPoint {
        fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
            reader: &mut R,
        ) -> Result<Self, bitcoin::consensus::encode::Error> {
            let mut txid = [0u8; 32];
            reader.read_exact(&mut txid)?;
            let mut vout = [0u8; 4];
            reader.read_exact(&mut vout)?;
            let txid = Txid::from_array(txid);
            let vout = u32::from_le_bytes(vout);
            Ok(Self::new(txid, vout))
        }
    }

    fn sample_outpoint() -> OutPoint {
        OutPoint::from_str("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:42")
            .unwrap()
    }

    #[test]
    fn test_outpoint_string_roundtrip() {
        let outpoint = sample_outpoint();
        assert_eq!(
            outpoint.to_string(),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:42"
        );
        assert_eq!(OutPoint::from_str(&outpoint.to_string()).unwrap(), outpoint);
    }

    #[test]
    fn test_outpoint_conversion_roundtrip() {
        let outpoint = sample_outpoint();
        assert_eq!(OutPoint::from(outpoint.bitcoin()), outpoint);
        assert_eq!(OutPoint::from(outpoint.elements()), outpoint);
    }

    #[test]
    fn test_outpoint_binary_encoding_matches_bitcoin_and_elements() {
        let outpoint = sample_outpoint();

        let ours = outpoint.to_bytes();
        let bitcoin = bitcoin_serialize(&outpoint.bitcoin());
        let elements = elements_serialize(&outpoint.elements());

        assert_eq!(bitcoin.len(), OutPoint::SIZE);
        assert_eq!(elements.len(), OutPoint::SIZE);
        assert_eq!(ours.as_slice(), bitcoin.as_slice());
        assert_eq!(ours.as_slice(), elements.as_slice());
    }

    #[test]
    fn test_outpoint_binary_decoding_matches_bitcoin_and_elements() {
        let outpoint = sample_outpoint();
        let bytes = outpoint.to_bytes();

        let from_bitcoin: bitcoin::OutPoint = bitcoin_deserialize(&bytes).unwrap();
        let from_elements: elements::OutPoint = elements_deserialize(&bytes).unwrap();

        assert_eq!(OutPoint::from(from_bitcoin), outpoint);
        assert_eq!(OutPoint::from(from_elements), outpoint);
    }

    #[test]
    fn test_outpoint_our_traits_match_bitcoin_and_elements_bytes() {
        let bitcoin_outpoint = bitcoin::OutPoint::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111:7",
        )
        .unwrap();
        let elements_outpoint = elements::OutPoint::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111:7",
        )
        .unwrap();
        let our_outpoint = OutPoint::from(bitcoin_outpoint);

        let bitcoin_bytes = bitcoin_serialize(&bitcoin_outpoint);
        let elements_bytes = elements_serialize(&elements_outpoint);
        let our_bitcoin_bytes = bitcoin_serialize(&our_outpoint);
        let our_elements_bytes = elements_serialize(&our_outpoint);

        assert_eq!(bitcoin_bytes, elements_bytes);
        assert_eq!(our_bitcoin_bytes, bitcoin_bytes);
        assert_eq!(our_elements_bytes, elements_bytes);
    }
}
