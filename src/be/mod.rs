mod address;
mod block;
mod block_header;
mod descriptor;
mod transaction;
mod txid;

pub use address::Address;
pub use block::Block;
pub use block_header::BlockHeader;
pub use descriptor::{bitcoin_descriptor, Descriptor};
pub use transaction::{Input, InputRef, Output, OutputRef, Transaction, TransactionRef};
pub use txid::Txid;

use crate::server::Network;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Bitcoin,
    Elements,
}

impl From<Network> for Family {
    fn from(network: Network) -> Self {
        match network {
            Network::Liquid | Network::LiquidTestnet | Network::ElementsRegtest => Family::Elements,
            Network::Bitcoin
            | Network::BitcoinTestnet
            | Network::BitcoinRegtest
            | Network::BitcoinSignet => Family::Bitcoin,
        }
    }
}
