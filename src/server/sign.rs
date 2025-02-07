use bitcoin::{
    key::Secp256k1,
    secp256k1::{All, Message},
    sign_message::{MessageSignature, MessageSignatureError},
};
use elements::bitcoin::{self, PrivateKey};

pub struct MessageAndSignature {
    pub message: Message,
    pub signature: MessageSignature,
}

// TODO accept response as &[u8]
pub(crate) fn sign_response(
    secp: &Secp256k1<All>,
    key: &PrivateKey,
    response: &str,
) -> MessageAndSignature {
    let digest = bitcoin::sign_message::signed_msg_hash(response);
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
    response: &str,
    signature: &MessageSignature,
) -> Result<bool, MessageSignatureError> {
    let msg_hash = bitcoin::sign_message::signed_msg_hash(response);

    signature.is_signed_by_address(&secp, address, msg_hash)
}

pub(crate) fn p2pkh(secp: &Secp256k1<All>, wif_key: &PrivateKey) -> bitcoin::Address {
    bitcoin::Address::p2pkh(&wif_key.public_key(&secp), wif_key.network)
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

        let m = sign_response(&secp, &private_key, response);

        let result = verify_response(&secp, &address, response, &m.signature).unwrap();
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
        let result = verify_response(&secp, &address, response, &signature).unwrap();
        assert!(result);
    }
}
