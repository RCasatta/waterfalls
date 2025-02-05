use bitcoin::{
    key::Secp256k1,
    secp256k1::{All, Message},
    sign_message::MessageSignature,
    NetworkKind,
};
use elements::bitcoin::{self, PrivateKey};

// TODO accept response as &[u8]
pub(crate) fn sign_response(
    secp: &Secp256k1<All>,
    key: &PrivateKey,
    response: &str,
) -> (Message, MessageSignature) {
    let digest = bitcoin::sign_message::signed_msg_hash(response);
    let digest = bitcoin::secp256k1::Message::from_digest_slice(digest.as_ref()).unwrap();
    let signature = secp.sign_ecdsa_recoverable(&digest, &key.inner);
    (
        digest,
        MessageSignature {
            signature,
            compressed: true,
        },
    )
}

// TODO accept response as &[u8]
pub(crate) fn verify_response(
    secp: &Secp256k1<All>,
    address: bitcoin::Address,
    response: &str,
    signature: &MessageSignature,
) -> bool {
    let msg_hash = bitcoin::sign_message::signed_msg_hash(response);

    signature
        .is_signed_by_address(&secp, &address, msg_hash)
        .unwrap()
}

pub(crate) fn p2pkh(secp: &Secp256k1<All>, wif_key: &PrivateKey) -> bitcoin::Address {
    bitcoin::Address::p2pkh(&wif_key.public_key(&secp), wif_key.network)
}

#[cfg(test)]
mod tests {
    use elements::bitcoin::NetworkKind;

    use super::*;

    #[test]
    fn test_sign_verify_response() {
        let response = "test";
        let secp = bitcoin::key::Secp256k1::new();
        let private_key = PrivateKey::generate(NetworkKind::Test);

        let address = p2pkh(&secp, &private_key);

        let (_digest, signature) = sign_response(&secp, &private_key, response);

        let result = verify_response(&secp, address, response, &signature);
        assert!(result);
    }
}
