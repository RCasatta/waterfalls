mod block;

pub use block::Block;

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
