use sodiumoxide::crypto::box_::{gen_nonce, open, seal, Nonce, PublicKey, SecretKey, NONCEBYTES};

use crate::{
    errors::{InternalError, Result},
    keyshare_export::Pke,
};

/// Libsodium-based implementation of the Pke trait
#[derive(Clone, Debug)]
pub struct SodiumPke;

impl Pke for SodiumPke {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;

    fn encrypt(
        plaintext: &[u8],
        receiver_pk: &Self::PublicKey,
        sender_sk: &Self::SecretKey,
    ) -> Result<Vec<u8>> {
        init()?;

        let nonce = gen_nonce();
        let ciphertext = seal(plaintext, &nonce, receiver_pk, sender_sk);

        let mut encrypted_data = nonce.0.to_vec();
        encrypted_data.extend(ciphertext);
        Ok(encrypted_data)
    }

    fn decrypt(
        ciphertext: &[u8],
        sender_pk: &Self::PublicKey,
        receiver_sk: &Self::SecretKey,
    ) -> Result<Vec<u8>> {
        init()?;

        let (nonce_bytes, ciphertext) = ciphertext.split_at(NONCEBYTES);
        let nonce = Nonce::from_slice(nonce_bytes).ok_or(InternalError::Serialization)?;

        let decrypted = open(ciphertext, &nonce, sender_pk, receiver_sk)
            .map_err(|_| InternalError::Serialization)?;

        Ok(decrypted)
    }
}

fn init() -> Result<()> {
    sodiumoxide::init().map_err(|_| InternalError::InternalInvariantFailed)
}
