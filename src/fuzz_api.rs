//! Internal functions exposed to the fuzz targets in `fuzz/`, only built with the `fuzz` feature.

use age::x25519::Identity;

use crate::be;
use crate::server::{route, Error, Network};
use crate::WaterfallRequest;

pub const MAX_DESCRIPTOR_LENGTH: usize = be::MAX_DESCRIPTOR_LENGTH;
pub const MAX_SINGLE_DESCRIPTORS: usize = be::MAX_SINGLE_DESCRIPTORS;

pub const NETWORKS: [Network; 8] = [
    Network::Liquid,
    Network::LiquidTestnet,
    Network::ElementsRegtest,
    Network::Bitcoin,
    Network::BitcoinTestnet,
    Network::BitcoinTestnet4,
    Network::BitcoinRegtest,
    Network::BitcoinSignet,
];

fn is_testnet_or_regtest(network: Network) -> bool {
    !matches!(network, Network::Liquid | Network::Bitcoin)
}

/// Same parsing done by the `/vN/waterfalls` endpoints.
pub fn parse_query(
    query: &str,
    key: &Identity,
    max_addresses: usize,
    network: Network,
) -> Result<WaterfallRequest, Error> {
    route::parse_query(
        query,
        key,
        is_testnet_or_regtest(network),
        max_addresses,
        network,
    )
}

/// Same parsing done by the `/v1/last_used_index` and `/v1/subscribe` endpoints.
pub fn parse_descriptor_query(
    query: &str,
    key: &Identity,
    network: Network,
) -> Result<be::Descriptor, Error> {
    route::parse_descriptor_query(query, key, is_testnet_or_regtest(network), network)
}

pub fn request_descriptor(request: &WaterfallRequest) -> Option<&be::Descriptor> {
    request.descriptor().map(|d| &d.descriptor)
}

pub fn request_addresses(request: &WaterfallRequest) -> Option<&[be::Address]> {
    request.addresses().map(|a| a.addresses.as_slice())
}

pub fn into_single_descriptors(descriptor: be::Descriptor) -> Result<Vec<be::Descriptor>, Error> {
    descriptor.into_single_descriptors()
}

pub fn script_pubkey_at_derivation_index(
    descriptor: &be::Descriptor,
    index: u32,
) -> Result<Vec<u8>, Error> {
    descriptor.script_pubkey_at_derivation_index(index)
}

pub fn address_at_derivation_index(
    descriptor: &be::Descriptor,
    index: u32,
    network: Network,
) -> Result<be::Address, Error> {
    descriptor.address_at_derivation_index(index, network)
}

pub fn has_wildcard(descriptor: &be::Descriptor) -> bool {
    descriptor.has_wildcard()
}

pub fn normalized_id_string(descriptor: &be::Descriptor) -> String {
    descriptor.normalized_id_string()
}

/// Same parsing done on the `POST /tx` body.
pub fn transaction_from_str(tx_hex: &str, family: be::Family) -> Result<(), anyhow::Error> {
    be::Transaction::from_str(tx_hex, family).map(|_| ())
}
