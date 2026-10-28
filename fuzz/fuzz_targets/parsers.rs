//! Parsers of path segments and request bodies: addresses, txids, outpoints and the
//! `POST /tx` body.
//!
//! Input: 1 byte selector, text.

#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use waterfalls::be::{Address, Family, OutPoint, Txid};
use waterfalls::fuzz_api::*;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, text)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(text) else {
        return;
    };
    let network = NETWORKS[(selector / 4) as usize % NETWORKS.len()];

    match selector % 4 {
        0 => {
            if let Ok(address) = Address::from_str(text, network) {
                let _ = address.ensure_not_blinded();
                let _ = address.to_unconfidential();
                let _ = address.to_string();
            }
        }
        1 => {
            if let Ok(txid) = Txid::from_str(text) {
                let roundtrip = Txid::from_str(&txid.to_string()).expect("display is parsable");
                assert_eq!(txid, roundtrip);
            }
        }
        2 => {
            if let Ok(outpoint) = OutPoint::from_str(text) {
                let roundtrip =
                    OutPoint::from_str(&outpoint.to_string()).expect("display is parsable");
                assert_eq!(outpoint, roundtrip);
            }
        }
        _ => {
            let family = if selector & 4 == 0 {
                Family::Bitcoin
            } else {
                Family::Elements
            };
            let _ = transaction_from_str(text, family);
        }
    }
});
