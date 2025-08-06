use crate::server::{Error, Network};

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
}

impl std::fmt::Display for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Descriptor::Bitcoin(desc) => desc.fmt(f),
            Descriptor::Elements(desc) => desc.fmt(f),
        }
    }
}

fn bitcoin_descriptor(s: &str) -> Result<Descriptor, Error> {
    let desc = s
        .parse::<miniscript::descriptor::Descriptor<miniscript::DescriptorPublicKey>>()
        .map_err(|e| Error::String(format!("{e:?}")))?;
    Ok(Descriptor::Bitcoin(desc))
}

fn elements_descriptor(s: &str) -> Result<Descriptor, Error> {
    let desc = s
        .parse::<elements_miniscript::descriptor::Descriptor<elements_miniscript::DescriptorPublicKey>>()
        .map_err(|e| Error::String(format!("{e:?}")))?;
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
        assert!(matches!(result, Err(Error::String(_))));

        let result = Descriptor::from_str("invalid_descriptor", Network::Liquid);
        assert!(matches!(result, Err(Error::String(_))));

        // Empty string
        let result = Descriptor::from_str("", Network::Bitcoin);
        assert!(matches!(result, Err(Error::String(_))));

        // Malformed descriptor
        let result = Descriptor::from_str("wpkh(", Network::Bitcoin);
        assert!(matches!(result, Err(Error::String(_))));
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
}
