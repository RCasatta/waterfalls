use age::x25519::{Identity, Recipient};
use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;
use std::io::{Read, Write};

use super::Error;

pub fn encrypt(plaintext: &str, recipient: Recipient) -> Result<String, Error> {
    let encryptor =
        age::Encryptor::with_recipients(vec![recipient].iter().map(|e| e as &dyn age::Recipient))
            .expect("we provided a recipient");

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|_| Error::CannotEncrypt)?;
    writer.write_all(plaintext.as_ref()).unwrap();
    writer.finish().map_err(|_| Error::CannotEncrypt)?;
    let result = BASE64_STANDARD_NO_PAD.encode(encrypted);
    Ok(result)
}
pub fn decrypt(base64_encrypted: &str, key: &Identity) -> Result<String, Error> {
    let encrypted = BASE64_STANDARD_NO_PAD
        .decode(base64_encrypted)
        .map_err(|_| Error::CannotDecrypt)?;

    let decryptor = age::Decryptor::new(&encrypted[..]).map_err(|_| Error::CannotDecrypt)?;

    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(std::iter::once(key as &dyn age::Identity))
        .map_err(|_| Error::CannotDecrypt)?;
    reader.read_to_end(&mut decrypted).unwrap();

    let result = std::str::from_utf8(&decrypted)
        .map_err(|_| Error::CannotDecrypt)?
        .to_string();
    Ok(result)
}

#[cfg(test)]
mod test {
    use age::x25519::Identity;

    use super::{decrypt, encrypt};

    #[test]
    fn test_enc_dec() {
        let idendity = Identity::generate();
        let recipient = idendity.to_public();
        let plaintext = "Hello world!";

        let encrypted = encrypt(plaintext, recipient).unwrap();

        let decrypted = decrypt(&encrypted, &idendity).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted, plaintext);
    }
}
