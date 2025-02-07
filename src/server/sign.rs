use bitcoin::{
    hashes::{sha256d, Hash, HashEngine},
    key::Secp256k1,
    secp256k1::{All, Message},
    sign_message::{MessageSignature, MessageSignatureError, BITCOIN_SIGNED_MSG_PREFIX},
};
use elements::{
    bitcoin::{self, PrivateKey},
    encode::{self, Encodable},
};

pub struct MessageAndSignature {
    pub message: Message,
    pub signature: MessageSignature,
}

// TODO accept response as &[u8]
pub(crate) fn sign_response(
    secp: &Secp256k1<All>,
    key: &PrivateKey,
    response: &[u8],
) -> MessageAndSignature {
    let digest = signed_msg_hash(response);
    let message =
        bitcoin::secp256k1::Message::from_digest_slice(digest.as_ref()).expect("digest is 32");
    let signature = secp.sign_ecdsa_recoverable(&message, &key.inner);
    let signature = MessageSignature {
        signature,
        compressed: true,
    };
    MessageAndSignature { message, signature }
}

// TODO accept response as &[u8]
pub fn verify_response(
    secp: &Secp256k1<All>,
    address: &bitcoin::Address,
    response: &[u8],
    signature: &MessageSignature,
) -> Result<bool, MessageSignatureError> {
    let msg_hash = signed_msg_hash(response);

    signature.is_signed_by_address(secp, address, msg_hash)
}

pub(crate) fn p2pkh(secp: &Secp256k1<All>, wif_key: &PrivateKey) -> bitcoin::Address {
    bitcoin::Address::p2pkh(wif_key.public_key(secp), wif_key.network)
}

/// Hash message for signature using Bitcoin's message signing format.
/// This is the same as bitcoin::sign_message::signed_msg_hash, but it accepts a slice of bytes instead of a string.
pub fn signed_msg_hash(msg: &[u8]) -> sha256d::Hash {
    let mut engine = sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    let msg_len = encode::VarInt(msg.len() as u64);
    msg_len
        .consensus_encode(&mut engine)
        .expect("engines don't error");
    engine.input(msg);
    sha256d::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {
    use elements::bitcoin::NetworkKind;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_sign_verify_response() {
        let response = "test";
        let secp = bitcoin::key::Secp256k1::new();
        let private_key = PrivateKey::generate(NetworkKind::Test);

        let address = p2pkh(&secp, &private_key);

        let m = sign_response(&secp, &private_key, response.as_bytes());

        let result = verify_response(&secp, &address, response.as_bytes(), &m.signature).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_fixed_values() {
        let address = "mj55KBETZ5vd5yVaWN9t9EEvJPsCmYVYCr";
        let response = "test";
        let signature = "IDL1hPIcEj6E9j/uXQugiGZem6fxZQQYALI0j1yQ+GqdaTKwvulr6eUuKkzmCDHzHdzFD8k3AVdL6/yzqyn9dZA=";
        let secp = bitcoin::key::Secp256k1::new();
        let address = bitcoin::Address::from_str(address)
            .unwrap()
            .assume_checked();
        let signature = MessageSignature::from_base64(signature).unwrap();
        let result = verify_response(&secp, &address, response.as_bytes(), &signature).unwrap();
        assert!(result);
    }
}
