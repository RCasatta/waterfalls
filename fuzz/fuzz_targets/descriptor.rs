//! Descriptor parsing and derivation, as done for the descriptor endpoints after decryption.
//!
//! Input: 1 byte network selector, 4 bytes derivation index (little endian), descriptor text.

#![no_main]

use libfuzzer_sys::fuzz_target;
use waterfalls::be::Descriptor;
use waterfalls::fuzz_api::*;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Some((index, text)) = rest.split_first_chunk::<4>() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(text) else {
        return;
    };
    let network = NETWORKS[selector as usize % NETWORKS.len()];
    let index = u32::from_le_bytes(*index);

    let Ok(descriptor) = Descriptor::from_str(text, network) else {
        return;
    };
    assert!(text.len() <= MAX_DESCRIPTOR_LENGTH);
    let _ = descriptor.is_mainnet();
    let _ = descriptor.to_string();

    let singles = into_single_descriptors(descriptor).expect("a parsed descriptor expands");
    assert!(singles.len() <= MAX_SINGLE_DESCRIPTORS);
    for single in singles.iter() {
        let _ = normalized_id_string(single);
        let _ = script_pubkey_at_derivation_index(single, index);
        let _ = address_at_derivation_index(single, index, network);
    }
});
