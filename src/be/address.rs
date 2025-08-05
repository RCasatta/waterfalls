use std::str::FromStr;

use elements::AddressParams;

use crate::server::{Error, Network};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Address {
    Bitcoin(bitcoin::Address),
    Elements(elements::Address),
}

impl Address {
    pub fn from_str(s: &str, network: Network) -> Result<Self, Error> {
        Ok(match network {
            Network::Liquid => liquid_address(s, &AddressParams::LIQUID)?,
            Network::LiquidTestnet => liquid_address(s, &AddressParams::LIQUID_TESTNET)?,
            Network::ElementsRegtest => liquid_address(s, &AddressParams::ELEMENTS)?,
            Network::Bitcoin => bitcoin_address(s, bitcoin::Network::Bitcoin)?,
            Network::BitcoinTestnet => bitcoin_address(s, bitcoin::Network::Testnet)?,
            Network::BitcoinRegtest => bitcoin_address(s, bitcoin::Network::Regtest)?,
            Network::BitcoinSignet => bitcoin_address(s, bitcoin::Network::Signet)?,
        })
    }

    // We are using elements::Script also for bitcoin script which is ugly but less impactfull for now
    pub(crate) fn script_pubkey(&self) -> elements::Script {
        match self {
            Address::Bitcoin(addr) => addr.script_pubkey().to_bytes().into(),
            Address::Elements(addr) => addr.script_pubkey().clone(),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Bitcoin(addr) => addr.fmt(f),
            Address::Elements(addr) => addr.fmt(f),
        }
    }
}

fn bitcoin_address(s: &str, network: bitcoin::Network) -> Result<Address, Error> {
    let addr = bitcoin::Address::from_str(s).map_err(|e| Error::String(format!("{e:?}")))?;
    let addr = addr
        .require_network(network)
        .map_err(|e| Error::String(format!("{e:?}")))?;
    Ok(Address::Bitcoin(addr))
}

fn liquid_address(s: &str, params: &'static AddressParams) -> Result<Address, Error> {
    let addr = elements::Address::from_str(s).map_err(|e| Error::String(format!("{e:?}")))?;
    if addr.params != params {
        return Err(Error::WrongNetwork);
    }
    if addr.is_blinded() {
        return Err(Error::AddressCannotBeBlinded);
    }
    Ok(Address::Elements(addr))
}
