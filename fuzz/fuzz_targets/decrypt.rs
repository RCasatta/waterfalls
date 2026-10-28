//! Decryption of age-encrypted descriptors sent by clients.
//!
//! Input: 1 byte mode, then
//! - even mode: the encrypted string as received in the query.
//! - odd mode: 2 bytes truncation length (little endian, 0 for none), 1 byte plaintext length,
//!   plaintext, then 3 byte (position, xor) bit flips.
//!   The plaintext is encrypted to the server key before truncation and flips are applied,
//!   so that the age header is valid and the payload is reached.

#![no_main]

use std::sync::OnceLock;

use age::x25519::Identity;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;
use libfuzzer_sys::fuzz_target;
use waterfalls::server::encryption::{decrypt, encrypt};
use waterfalls::server::route::is_likely_age_encrypted;

fn key() -> &'static Identity {
    static KEY: OnceLock<Identity> = OnceLock::new();
    KEY.get_or_init(Identity::generate)
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        let Ok(input) = std::str::from_utf8(rest) else {
            return;
        };
        if is_likely_age_encrypted(input) {
            let _ = decrypt(input, key());
        }
        return;
    }

    let Some((truncate, rest)) = rest.split_first_chunk::<2>() else {
        return;
    };
    let Some((&plaintext_len, rest)) = rest.split_first() else {
        return;
    };
    let Some((plaintext, flips)) = rest.split_at_checked(plaintext_len as usize) else {
        return;
    };
    let plaintext = String::from_utf8_lossy(plaintext);
    let truncate = u16::from_le_bytes(*truncate) as usize;

    let encrypted = encrypt(&plaintext, key().to_public()).expect("encrypting cannot fail");
    let mut bytes = BASE64_STANDARD_NO_PAD
        .decode(encrypted)
        .expect("encrypt returns base64");
    let mut changed = false;
    if truncate != 0 && truncate < bytes.len() {
        bytes.truncate(truncate);
        changed = true;
    }
    for flip in flips.chunks_exact(3) {
        let position = u16::from_le_bytes([flip[0], flip[1]]) as usize;
        if let Some(byte) = bytes.get_mut(position) {
            *byte ^= flip[2];
            changed |= flip[2] != 0;
        }
    }
    let input = BASE64_STANDARD_NO_PAD.encode(bytes);

    let result = decrypt(&input, key());
    if !changed {
        assert_eq!(result.as_deref(), Ok(plaintext.as_ref()));
    }
});
