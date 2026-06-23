use std::convert::Infallible;

use crate::server::{Error, Network};
use elements_miniscript::TranslatePk as ElementsTranslatePk;
use miniscript::{ForEachKey, TranslatePk as BitcoinTranslatePk};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Descriptor {
    Bitcoin(miniscript::descriptor::Descriptor<miniscript::DescriptorPublicKey>),
    Elements(elements_miniscript::descriptor::Descriptor<elements_miniscript::DescriptorPublicKey>),
}

impl Descriptor {
    pub fn from_str(s: &str, network: Network) -> Result<Self, Error> {
        Ok(match network {
            Network::Liquid => elements_descriptor(s)?,
            Network::LiquidTestnet => elements_descriptor(s)?,
            Network::ElementsRegtest => elements_descriptor(s)?,
            Network::Bitcoin => bitcoin_descriptor(s)?,
            Network::BitcoinTestnet => bitcoin_descriptor(s)?,
            Network::BitcoinRegtest => bitcoin_descriptor(s)?,
            Network::BitcoinSignet => bitcoin_descriptor(s)?,
        })
    }

    pub fn bitcoin(
        &self,
    ) -> Option<&miniscript::descriptor::Descriptor<miniscript::DescriptorPublicKey>> {
        match self {
            Descriptor::Bitcoin(desc) => Some(desc),
            Descriptor::Elements(_) => None,
        }
    }

    pub fn elements(
        &self,
    ) -> Option<
        &elements_miniscript::descriptor::Descriptor<elements_miniscript::DescriptorPublicKey>,
    > {
        match self {
            Descriptor::Bitcoin(_) => None,
            Descriptor::Elements(desc) => Some(desc),
        }
    }

    pub(crate) fn into_single_descriptors(self) -> Result<Vec<Self>, Error> {
        Ok(match self {
            Descriptor::Bitcoin(desc) => {
                let desc = desc
                    .clone()
                    .into_single_descriptors()
                    .map_err(|e| Error::String(e.to_string()))?;
                desc.into_iter().map(Descriptor::Bitcoin).collect()
            }
            Descriptor::Elements(desc) => {
                let desc = desc
                    .clone()
                    .into_single_descriptors()
                    .map_err(|e| Error::String(e.to_string()))?;
                desc.into_iter().map(Descriptor::Elements).collect()
            }
        })
    }

    pub(crate) fn script_pubkey_at_derivation_index(&self, index: u32) -> Result<Vec<u8>, Error> {
        Ok(match self {
            Descriptor::Bitcoin(desc) => desc
                .at_derivation_index(index)
                .map_err(|e| Error::String(e.to_string()))?
                .script_pubkey()
                .as_bytes()
                .to_vec(),

            Descriptor::Elements(desc) => desc
                .at_derivation_index(index)
                .map_err(|e| Error::String(e.to_string()))?
                .script_pubkey()
                .as_bytes()
                .to_vec(),
        })
    }

    pub(crate) fn address_at_derivation_index(
        &self,
        index: u32,
        network: Network,
    ) -> Result<crate::be::Address, Error> {
        let script_pubkey = self.script_pubkey_at_derivation_index(index)?;
        crate::be::Address::from_script(&script_pubkey.into(), network)
            .ok_or_else(|| Error::String("Cannot derive address from script".to_string()))
    }

    pub(crate) fn has_wildcard(&self) -> bool {
        match self {
            Descriptor::Bitcoin(desc) => desc.has_wildcard(),
            Descriptor::Elements(desc) => desc.has_wildcard(),
        }
    }

    pub(crate) fn normalized_id_string(&self) -> String {
        // ELIP-0152 DWID is the better wallet-level identifier for CT descriptors, but
        // computing it requires the blinding key. Waterfalls intentionally receives only
        // the unblinded descriptor, so we normalize just enough for server-side scan ids.
        match self {
            Descriptor::Bitcoin(desc) => desc
                .translate_pk(&mut BitcoinOriginStripper)
                .expect("removing key origin from bitcoin descriptor cannot fail")
                .to_string(),
            Descriptor::Elements(desc) => desc
                .translate_pk(&mut ElementsOriginStripper)
                .expect("removing key origin from elements descriptor cannot fail")
                .to_string(),
        }
    }

    /// Returns true if all the xpubs in the descriptor are for mainnet.
    /// Returns true if there are no xpubs (e.g., only single keys).
    pub fn is_mainnet(&self) -> bool {
        match self {
            Descriptor::Bitcoin(desc) => desc.for_each_key(|k| match k {
                miniscript::DescriptorPublicKey::XPub(x) => {
                    x.xkey.network == bitcoin::NetworkKind::Main
                }
                miniscript::DescriptorPublicKey::MultiXPub(x) => {
                    x.xkey.network == bitcoin::NetworkKind::Main
                }
                miniscript::DescriptorPublicKey::Single(_) => true,
            }),
            Descriptor::Elements(desc) => desc.for_each_key(|k| match k {
                elements_miniscript::DescriptorPublicKey::XPub(x) => {
                    x.xkey.network == bitcoin::NetworkKind::Main
                }
                elements_miniscript::DescriptorPublicKey::MultiXPub(x) => {
                    x.xkey.network == bitcoin::NetworkKind::Main
                }
                elements_miniscript::DescriptorPublicKey::Single(_) => true,
            }),
        }
    }
}

struct BitcoinOriginStripper;

impl
    miniscript::Translator<
        miniscript::DescriptorPublicKey,
        miniscript::DescriptorPublicKey,
        Infallible,
    > for BitcoinOriginStripper
{
    fn pk(
        &mut self,
        pk: &miniscript::DescriptorPublicKey,
    ) -> Result<miniscript::DescriptorPublicKey, Infallible> {
        Ok(strip_bitcoin_key_origin(pk))
    }

    fn sha256(
        &mut self,
        sha256: &<miniscript::DescriptorPublicKey as miniscript::MiniscriptKey>::Sha256,
    ) -> Result<<miniscript::DescriptorPublicKey as miniscript::MiniscriptKey>::Sha256, Infallible>
    {
        Ok(*sha256)
    }

    fn hash256(
        &mut self,
        hash256: &<miniscript::DescriptorPublicKey as miniscript::MiniscriptKey>::Hash256,
    ) -> Result<<miniscript::DescriptorPublicKey as miniscript::MiniscriptKey>::Hash256, Infallible>
    {
        Ok(*hash256)
    }

    fn ripemd160(
        &mut self,
        ripemd160: &<miniscript::DescriptorPublicKey as miniscript::MiniscriptKey>::Ripemd160,
    ) -> Result<<miniscript::DescriptorPublicKey as miniscript::MiniscriptKey>::Ripemd160, Infallible>
    {
        Ok(*ripemd160)
    }

    fn hash160(
        &mut self,
        hash160: &<miniscript::DescriptorPublicKey as miniscript::MiniscriptKey>::Hash160,
    ) -> Result<<miniscript::DescriptorPublicKey as miniscript::MiniscriptKey>::Hash160, Infallible>
    {
        Ok(*hash160)
    }
}

fn strip_bitcoin_key_origin(
    key: &miniscript::DescriptorPublicKey,
) -> miniscript::DescriptorPublicKey {
    match key {
        miniscript::DescriptorPublicKey::Single(single) => {
            let mut single = single.clone();
            single.origin = None;
            miniscript::DescriptorPublicKey::Single(single)
        }
        miniscript::DescriptorPublicKey::XPub(xpub) => {
            let mut xpub = xpub.clone();
            xpub.origin = None;
            miniscript::DescriptorPublicKey::XPub(xpub)
        }
        miniscript::DescriptorPublicKey::MultiXPub(xpub) => {
            let mut xpub = xpub.clone();
            xpub.origin = None;
            miniscript::DescriptorPublicKey::MultiXPub(xpub)
        }
    }
}

struct ElementsOriginStripper;

impl
    elements_miniscript::Translator<
        elements_miniscript::DescriptorPublicKey,
        elements_miniscript::DescriptorPublicKey,
        Infallible,
    > for ElementsOriginStripper
{
    fn pk(
        &mut self,
        pk: &elements_miniscript::DescriptorPublicKey,
    ) -> Result<elements_miniscript::DescriptorPublicKey, Infallible> {
        Ok(strip_elements_key_origin(pk))
    }

    fn sha256(
        &mut self,
        sha256: &<elements_miniscript::DescriptorPublicKey as elements_miniscript::MiniscriptKey>::Sha256,
    ) -> Result<
        <elements_miniscript::DescriptorPublicKey as elements_miniscript::MiniscriptKey>::Sha256,
        Infallible,
    > {
        Ok(*sha256)
    }

    fn hash256(
        &mut self,
        hash256: &<elements_miniscript::DescriptorPublicKey as elements_miniscript::MiniscriptKey>::Hash256,
    ) -> Result<
        <elements_miniscript::DescriptorPublicKey as elements_miniscript::MiniscriptKey>::Hash256,
        Infallible,
    > {
        Ok(*hash256)
    }

    fn ripemd160(
        &mut self,
        ripemd160: &<elements_miniscript::DescriptorPublicKey as elements_miniscript::MiniscriptKey>::Ripemd160,
    ) -> Result<
        <elements_miniscript::DescriptorPublicKey as elements_miniscript::MiniscriptKey>::Ripemd160,
        Infallible,
    > {
        Ok(*ripemd160)
    }

    fn hash160(
        &mut self,
        hash160: &<elements_miniscript::DescriptorPublicKey as elements_miniscript::MiniscriptKey>::Hash160,
    ) -> Result<
        <elements_miniscript::DescriptorPublicKey as elements_miniscript::MiniscriptKey>::Hash160,
        Infallible,
    > {
        Ok(*hash160)
    }
}

fn strip_elements_key_origin(
    key: &elements_miniscript::DescriptorPublicKey,
) -> elements_miniscript::DescriptorPublicKey {
    match key {
        elements_miniscript::DescriptorPublicKey::Single(single) => {
            let mut single = single.clone();
            single.origin = None;
            elements_miniscript::DescriptorPublicKey::Single(single)
        }
        elements_miniscript::DescriptorPublicKey::XPub(xpub) => {
            let mut xpub = xpub.clone();
            xpub.origin = None;
            elements_miniscript::DescriptorPublicKey::XPub(xpub)
        }
        elements_miniscript::DescriptorPublicKey::MultiXPub(xpub) => {
            let mut xpub = xpub.clone();
            xpub.origin = None;
            elements_miniscript::DescriptorPublicKey::MultiXPub(xpub)
        }
    }
}

impl std::fmt::Display for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Descriptor::Bitcoin(desc) => desc.fmt(f),
            Descriptor::Elements(desc) => desc.fmt(f),
        }
    }
}

pub fn bitcoin_descriptor(s: &str) -> Result<Descriptor, Error> {
    let desc = s
        .parse::<miniscript::descriptor::Descriptor<miniscript::DescriptorPublicKey>>()
        .map_err(|e| Error::InvalidDescriptor(format!("{e:?}")))?;
    Ok(Descriptor::Bitcoin(desc))
}

fn elements_descriptor(s: &str) -> Result<Descriptor, Error> {
    if s.trim_start().starts_with("ct(") {
        return Err(Error::InvalidDescriptor(
            "Confidential descriptors with blinding keys are refused to preserve your privacy; pass the inner descriptor without ct(...)".to_string(),
        ));
    }

    let desc = s
        .parse::<elements_miniscript::descriptor::Descriptor<elements_miniscript::DescriptorPublicKey>>()
        .map_err(|e| Error::InvalidDescriptor(format!("{e:?}")))?;
    Ok(Descriptor::Elements(desc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_descriptors() {
        // Bitcoin P2WPKH descriptor
        let desc_str = "wpkh(02e18f242c8b0b589bfffeac30e1baa80a60933a649c7fb0f1103e78fbf58aa0ed)";
        let desc = Descriptor::from_str(desc_str, Network::Bitcoin).unwrap();
        assert!(matches!(desc, Descriptor::Bitcoin(_)));
        // Bitcoin descriptors include checksums in their string representation
        assert!(desc.to_string().starts_with(desc_str));
        assert!(desc.to_string().contains("#"));

        // Bitcoin P2WSH descriptor
        let desc_str = "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))";
        let desc = Descriptor::from_str(desc_str, Network::Bitcoin).unwrap();
        assert!(matches!(desc, Descriptor::Bitcoin(_)));
        assert!(desc.to_string().starts_with(desc_str));
        assert!(desc.to_string().contains("#"));
    }

    #[test]
    fn test_bitcoin_testnet_descriptors() {
        // Bitcoin testnet descriptor
        let desc_str = "wpkh(02e18f242c8b0b589bfffeac30e1baa80a60933a649c7fb0f1103e78fbf58aa0ed)";
        let desc = Descriptor::from_str(desc_str, Network::BitcoinTestnet).unwrap();
        assert!(matches!(desc, Descriptor::Bitcoin(_)));
        assert!(desc.to_string().starts_with(desc_str));
        assert!(desc.to_string().contains("#"));
    }

    #[test]
    fn test_bitcoin_regtest_descriptors() {
        // Bitcoin regtest descriptor
        let desc_str = "wpkh(02e18f242c8b0b589bfffeac30e1baa80a60933a649c7fb0f1103e78fbf58aa0ed)";
        let desc = Descriptor::from_str(desc_str, Network::BitcoinRegtest).unwrap();
        assert!(matches!(desc, Descriptor::Bitcoin(_)));
        assert!(desc.to_string().starts_with(desc_str));
        assert!(desc.to_string().contains("#"));
    }

    #[test]
    fn test_bitcoin_signet_descriptors() {
        // Bitcoin signet descriptor
        let desc_str = "wpkh(02e18f242c8b0b589bfffeac30e1baa80a60933a649c7fb0f1103e78fbf58aa0ed)";
        let desc = Descriptor::from_str(desc_str, Network::BitcoinSignet).unwrap();
        assert!(matches!(desc, Descriptor::Bitcoin(_)));
        assert!(desc.to_string().starts_with(desc_str));
        assert!(desc.to_string().contains("#"));
    }

    #[test]
    fn test_elements_descriptors() {
        // Elements/Liquid descriptor - using valid examples from the codebase
        let desc_str = "elwpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)#20ufqv7z";
        let desc = Descriptor::from_str(desc_str, Network::Liquid).unwrap();
        assert!(matches!(desc, Descriptor::Elements(_)));
        assert_eq!(desc.to_string(), desc_str);
    }

    #[test]
    fn test_liquid_testnet_descriptors() {
        // Liquid testnet descriptor - using valid example from codebase
        let desc_str = "elwpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)#v7pu3vak";
        let desc = Descriptor::from_str(desc_str, Network::LiquidTestnet).unwrap();
        assert!(matches!(desc, Descriptor::Elements(_)));
        assert_eq!(desc.to_string(), desc_str);
    }

    #[test]
    fn test_elements_regtest_descriptors() {
        // Elements regtest descriptor - using valid example from codebase
        let desc_str = "elwpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)#v7pu3vak";
        let desc = Descriptor::from_str(desc_str, Network::ElementsRegtest).unwrap();
        assert!(matches!(desc, Descriptor::Elements(_)));
        assert_eq!(desc.to_string(), desc_str);
    }

    #[test]
    fn test_invalid_descriptors() {
        // Completely invalid descriptor
        let result = Descriptor::from_str("invalid_descriptor", Network::Bitcoin);
        assert!(matches!(result, Err(Error::InvalidDescriptor(_))));

        let result = Descriptor::from_str("invalid_descriptor", Network::Liquid);
        assert!(matches!(result, Err(Error::InvalidDescriptor(_))));

        // Empty string
        let result = Descriptor::from_str("", Network::Bitcoin);
        assert!(matches!(result, Err(Error::InvalidDescriptor(_))));

        // Malformed descriptor
        let result = Descriptor::from_str("wpkh(", Network::Bitcoin);
        assert!(matches!(result, Err(Error::InvalidDescriptor(_))));
    }

    #[test]
    fn test_confidential_descriptor_rejected() {
        let desc_str = "ct(slip77(1bda6cd71a1e206e3eb793e5a4d98a46c3fa473c9ab7bdef9bb9c814764d6614),elwpkh([cb4ba44a/84'/1'/0']tpubDDrybtUajFcgXC85rvwPsh1oU7Azx4kJ9BAiRzMbByqK7UnVXY3gDRJPwEDfaQwguNUZFzrhavJGgEhbsfuebyxUSZQnjLezWVm2Vdqb7UM/<0;1>/*))#za9ktavp";
        let result = Descriptor::from_str(desc_str, Network::LiquidTestnet);

        assert!(matches!(
            result,
            Err(Error::InvalidDescriptor(message))
                if message.contains("without ct(...)")
        ));
    }

    #[test]
    fn test_normalized_id_string_ignores_elements_key_origin() {
        let with_origin = "elwpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)";
        let without_origin = "elwpkh(xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)";

        let with_origin = Descriptor::from_str(with_origin, Network::Liquid).unwrap();
        let without_origin = Descriptor::from_str(without_origin, Network::Liquid).unwrap();

        assert_ne!(with_origin.to_string(), without_origin.to_string());
        assert_eq!(
            with_origin.normalized_id_string(),
            without_origin.normalized_id_string()
        );
    }

    #[test]
    fn test_normalized_id_string_ignores_bitcoin_key_origin() {
        let with_origin = "wpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)";
        let without_origin = "wpkh(xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)";

        let with_origin = Descriptor::from_str(with_origin, Network::Bitcoin).unwrap();
        let without_origin = Descriptor::from_str(without_origin, Network::Bitcoin).unwrap();

        assert_ne!(with_origin.to_string(), without_origin.to_string());
        assert_eq!(
            with_origin.normalized_id_string(),
            without_origin.normalized_id_string()
        );
    }

    #[test]
    fn test_accessor_methods() {
        // Test bitcoin accessor
        let desc_str = "wpkh(02e18f242c8b0b589bfffeac30e1baa80a60933a649c7fb0f1103e78fbf58aa0ed)";
        let desc = Descriptor::from_str(desc_str, Network::Bitcoin).unwrap();
        assert!(desc.bitcoin().is_some());
        assert!(desc.elements().is_none());

        // Test elements accessor
        let desc_str = "elwpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)#20ufqv7z";
        let desc = Descriptor::from_str(desc_str, Network::Liquid).unwrap();
        assert!(desc.bitcoin().is_none());
        assert!(desc.elements().is_some());
    }

    #[test]
    fn test_display() {
        // Test that Display implementation works correctly
        let desc_str = "wpkh(02e18f242c8b0b589bfffeac30e1baa80a60933a649c7fb0f1103e78fbf58aa0ed)";
        let desc = Descriptor::from_str(desc_str, Network::Bitcoin).unwrap();
        // Bitcoin descriptors include checksums
        assert!(desc.to_string().starts_with(desc_str));
        assert!(desc.to_string().contains("#"));

        let desc_str = "elwpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)#20ufqv7z";
        let desc = Descriptor::from_str(desc_str, Network::Liquid).unwrap();
        assert_eq!(format!("{}", desc), desc_str);
    }

    #[test]
    fn test_is_mainnet() {
        // Elements descriptor with xpub (mainnet)
        let desc_str = "elwpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)#20ufqv7z";
        let desc = Descriptor::from_str(desc_str, Network::Liquid).unwrap();
        assert!(desc.is_mainnet());

        // Elements descriptor with tpub (testnet)
        let desc_str = "elwpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)#v7pu3vak";
        let desc = Descriptor::from_str(desc_str, Network::LiquidTestnet).unwrap();
        assert!(!desc.is_mainnet());

        // Descriptor with single key (no xpub) should return true
        let desc_str = "wpkh(02e18f242c8b0b589bfffeac30e1baa80a60933a649c7fb0f1103e78fbf58aa0ed)";
        let desc = Descriptor::from_str(desc_str, Network::Bitcoin).unwrap();
        assert!(desc.is_mainnet());
    }
}
