//! Query string parsing of the `/vN/waterfalls`, `/v1/last_used_index` and `/v1/subscribe`
//! endpoints.
//!
//! Input: 1 byte network selector, query string.

#![no_main]

use std::sync::OnceLock;

use age::x25519::Identity;
use libfuzzer_sys::fuzz_target;
use waterfalls::fuzz_api::*;

/// Default of `--max-addresses`
const MAX_ADDRESSES: usize = 100;

fn key() -> &'static Identity {
    static KEY: OnceLock<Identity> = OnceLock::new();
    KEY.get_or_init(Identity::generate)
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, query)) = data.split_first() else {
        return;
    };
    let Ok(query) = std::str::from_utf8(query) else {
        return;
    };
    let network = NETWORKS[selector as usize % NETWORKS.len()];

    if let Ok(request) = parse_query(query, key(), MAX_ADDRESSES, network) {
        if let Some(descriptor) = request_descriptor(&request) {
            let singles =
                into_single_descriptors(descriptor.clone()).expect("a parsed descriptor expands");
            assert!(singles.len() <= MAX_SINGLE_DESCRIPTORS);
        }
        if let Some(addresses) = request_addresses(&request) {
            assert!(!addresses.is_empty());
            assert!(addresses.len() <= MAX_ADDRESSES);
            for address in addresses {
                assert!(address.ensure_not_blinded().is_ok());
            }
        }
    }

    if let Ok(descriptor) = parse_descriptor_query(query, key(), network) {
        assert!(has_wildcard(&descriptor));
        let singles = into_single_descriptors(descriptor).expect("a parsed descriptor expands");
        assert!(singles.len() <= MAX_SINGLE_DESCRIPTORS);
    }
});
