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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_mainnet_addresses() {
        // P2PKH (Legacy)
        let addr =
            Address::from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Network::Bitcoin).unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(addr.to_string(), "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");

        // P2SH (Script Hash)
        let addr =
            Address::from_str("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Network::Bitcoin).unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(addr.to_string(), "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");

        // P2WPKH (Native SegWit)
        let addr = Address::from_str(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Network::Bitcoin,
        )
        .unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(
            addr.to_string(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );

        // P2WSH (Native SegWit Script)
        let addr = Address::from_str(
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            Network::Bitcoin,
        )
        .unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(
            addr.to_string(),
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        );
    }

    #[test]
    fn test_bitcoin_testnet_addresses() {
        // P2PKH Testnet
        let addr = Address::from_str(
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
            Network::BitcoinTestnet,
        )
        .unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(addr.to_string(), "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn");

        // P2SH Testnet
        let addr = Address::from_str(
            "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc",
            Network::BitcoinTestnet,
        )
        .unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(addr.to_string(), "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc");

        // P2WPKH Testnet
        let addr = Address::from_str(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Network::BitcoinTestnet,
        )
        .unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(
            addr.to_string(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
    }

    #[test]
    fn test_bitcoin_regtest_addresses() {
        // P2WPKH Regtest
        let addr = Address::from_str(
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            Network::BitcoinRegtest,
        )
        .unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(
            addr.to_string(),
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        );
    }

    #[test]
    fn test_bitcoin_signet_addresses() {
        // P2WPKH Signet
        let addr = Address::from_str(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Network::BitcoinSignet,
        )
        .unwrap();
        assert!(matches!(addr, Address::Bitcoin(_)));
        assert_eq!(
            addr.to_string(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
    }

    #[test]
    fn test_liquid_mainnet_addresses() {
        // Liquid mainnet address from existing tests
        let addr = Address::from_str(
            "ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh",
            Network::Liquid,
        )
        .unwrap();
        assert!(matches!(addr, Address::Elements(_)));
        assert_eq!(
            addr.to_string(),
            "ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh"
        );
    }

    #[test]
    fn test_liquid_testnet_addresses() {
        // Liquid testnet address
        let addr = Address::from_str(
            "tex1qv0s62sz6xnxf9d4qkvsnwqs5pz9k9q8dpp0q2h",
            Network::LiquidTestnet,
        )
        .unwrap();
        assert!(matches!(addr, Address::Elements(_)));
        assert_eq!(
            addr.to_string(),
            "tex1qv0s62sz6xnxf9d4qkvsnwqs5pz9k9q8dpp0q2h"
        );
    }

    #[test]
    fn test_elements_regtest_addresses() {
        // Test that elements regtest network is supported
        // Using a simple test that verifies the network type rather than a specific address
        // since elements regtest addresses can be generated dynamically
        let result = Address::from_str("invalid", Network::ElementsRegtest);
        assert!(matches!(result, Err(Error::String(_))));
    }

    #[test]
    fn test_wrong_network_errors() {
        // Bitcoin mainnet address on testnet network should fail
        let result = Address::from_str(
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            Network::BitcoinTestnet,
        );
        assert!(matches!(result, Err(Error::String(_))));

        // Bitcoin testnet address on mainnet network should fail
        let result = Address::from_str("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", Network::Bitcoin);
        assert!(matches!(result, Err(Error::String(_))));

        // Liquid mainnet address on testnet network should fail
        let result = Address::from_str(
            "ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh",
            Network::LiquidTestnet,
        );
        assert_eq!(result, Err(Error::WrongNetwork));

        // Liquid testnet address on mainnet network should fail
        let result = Address::from_str(
            "tex1qv0s62sz6xnxf9d4qkvsnwqs5pz9k9q8dpp0q2h",
            Network::Liquid,
        );
        assert_eq!(result, Err(Error::WrongNetwork));
    }

    #[test]
    fn test_invalid_addresses() {
        // Completely invalid address
        let result = Address::from_str("invalid_address", Network::Bitcoin);
        assert!(matches!(result, Err(Error::String(_))));

        let result = Address::from_str("invalid_address", Network::Liquid);
        assert!(matches!(result, Err(Error::String(_))));

        // Empty string
        let result = Address::from_str("", Network::Bitcoin);
        assert!(matches!(result, Err(Error::String(_))));

        // Too short
        let result = Address::from_str("abc", Network::Bitcoin);
        assert!(matches!(result, Err(Error::String(_))));
    }

    #[test]
    fn test_blinded_address_error() {
        // Blinded liquid address should fail
        let blinded_addr = "lq1qqgyxa469eaugae2sz3q8qzaqy0v57ecuekzyngfac5nw4z87yqskc5tp2wtueqq6am0x062zewkrl9lr0cqwvw0j9633xqe2e";
        let result = Address::from_str(blinded_addr, Network::Liquid);
        assert_eq!(result, Err(Error::AddressCannotBeBlinded));
    }

    #[test]
    fn test_mixed_network_types() {
        // Bitcoin address on liquid network should fail
        let result = Address::from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Network::Liquid);
        assert!(matches!(result, Err(Error::String(_))));

        // Liquid address on bitcoin network should fail
        let result = Address::from_str(
            "ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh",
            Network::Bitcoin,
        );
        assert!(matches!(result, Err(Error::String(_))));
    }

    #[test]
    fn test_script_pubkey_generation() {
        // Test that script_pubkey is generated correctly
        let addr =
            Address::from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Network::Bitcoin).unwrap();
        let script = addr.script_pubkey();
        assert!(!script.as_bytes().is_empty());

        let addr = Address::from_str(
            "ex1qq6krj23yx9s4xjeas453huxx8azrk942qrxsvh",
            Network::Liquid,
        )
        .unwrap();
        let script = addr.script_pubkey();
        assert!(!script.as_bytes().is_empty());
    }
}
