use std::str::FromStr;

use bitcoin::hashes::sha256d;

/// A transaction identifier.
///
/// This type don't discriminate between bitcoin and elements, so that in binary format doesn't occupy more space.
pub struct Txid(sha256d::Hash);

impl Txid {
    pub fn bitcoin(self) -> bitcoin::Txid {
        bitcoin::Txid::from_raw_hash(self.0)
    }

    pub fn elements(self) -> elements::Txid {
        elements::Txid::from_raw_hash(self.0)
    }
}

impl FromStr for Txid {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Txid(sha256d::Hash::from_str(s)?))
    }
}
