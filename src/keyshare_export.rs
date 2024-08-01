//! Module to export and import key shares, with encryption in transit.

use std::ops::Deref;

use crate::{
    errors::{InternalError, Result},
    keygen::KeySharePrivate,
};
use sodiumoxide::crypto::{
    box_,
    box_::{Nonce, PublicKey, SecretKey},
};

/// Struct for handling encrypted KeySharePrivate export and import
#[derive(Clone, Debug)]
pub struct KeyShareEncrypted(Vec<u8>);

impl From<Vec<u8>> for KeyShareEncrypted {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl From<KeyShareEncrypted> for Vec<u8> {
    fn from(encrypted: KeyShareEncrypted) -> Vec<u8> {
        encrypted.0
    }
}

impl Deref for KeyShareEncrypted {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl KeyShareEncrypted {
    /// Export a `KeySharePrivate` structure by serializing and encrypting it.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The private key share to export.
    /// * `receiver_pk` - The public key of the receiver for encryption.
    /// * `sender_sk` - The private key of the sender for encryption.
    ///
    /// # Returns
    ///
    /// An encrypted byte vector of the serialized KeySharePrivate.
    ///
    /// # Example
    ///
    /// ```
    /// use sodiumoxide::crypto::box_;
    /// use tss_ecdsa::keygen::KeySharePrivate;
    /// use tss_ecdsa::keyshare_export::KeyShareEncrypted;
    ///
    /// sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    /// let (sender_pk, sender_sk) = box_::gen_keypair();
    /// let (receiver_pk, receiver_sk) = box_::gen_keypair();
    /// let mut rng = rand::thread_rng();
    /// let key_share = KeySharePrivate::random(&mut rng);
    /// let encrypted = KeyShareEncrypted::export_keyshare(&key_share, &receiver_pk, &sender_sk)
    ///     .expect("Failed to export keyshare");
    /// ```
    pub fn export_keyshare(
        key_share: &KeySharePrivate,
        receiver_pk: &PublicKey,
        sender_sk: &SecretKey,
    ) -> Result<Self> {
        sodium_init()?;
        // Serialize the KeySharePrivate to bytes
        let serialized = key_share.clone().into_bytes();

        // Generate a nonce
        let nonce = box_::gen_nonce();

        // Encrypt the serialized bytes
        let ciphertext = box_::seal(&serialized, &nonce, receiver_pk, sender_sk);

        // Prepend the nonce to the ciphertext
        let mut encrypted_data = nonce.0.to_vec();
        encrypted_data.extend(ciphertext);

        Ok(Self(encrypted_data))
    }

    /// Import a `KeySharePrivate` structure by decrypting and deserializing it.
    ///
    /// # Arguments
    ///
    /// * `encrypted_key_share` - The encrypted byte vector of the
    ///   KeySharePrivate.
    /// * `sender_pk` - The public key of the sender for decryption.
    /// * `receiver_sk` - The private key of the receiver for decryption.
    ///
    /// # Returns
    ///
    /// A `KeySharePrivate` object.
    ///
    /// # Example
    ///
    /// ```
    /// use sodiumoxide::crypto::box_;
    /// use tss_ecdsa::keygen::KeySharePrivate;
    /// use tss_ecdsa::keyshare_export::KeyShareEncrypted;
    ///
    /// sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    /// let (sender_pk, sender_sk) = box_::gen_keypair();
    /// let (receiver_pk, receiver_sk) = box_::gen_keypair();
    /// let mut rng = rand::thread_rng();
    /// let key_share = KeySharePrivate::random(&mut rng);
    /// let encrypted = KeyShareEncrypted::export_keyshare(&key_share, &receiver_pk, &sender_sk)
    ///     .expect("Failed to export keyshare");
    /// let decrypted = KeyShareEncrypted::import_keyshare(&encrypted, &sender_pk, &receiver_sk)
    ///     .expect("Failed to import keyshare");
    /// assert_eq!(key_share, decrypted);
    /// ```
    pub fn import_keyshare(
        encrypted_key_share: &Self,
        sender_pk: &PublicKey,
        receiver_sk: &SecretKey,
    ) -> Result<KeySharePrivate> {
        sodium_init()?;
        // Split the nonce and the ciphertext
        let (nonce_bytes, ciphertext) = encrypted_key_share.0.split_at(box_::NONCEBYTES);
        let nonce = Nonce::from_slice(nonce_bytes).ok_or(InternalError::InternalInvariantFailed)?;

        // Decrypt the ciphertext
        let decrypted = box_::open(ciphertext, &nonce, sender_pk, receiver_sk)
            .map_err(|_| InternalError::Serialization)?;

        // Deserialize the KeySharePrivate from bytes
        KeySharePrivate::try_from_bytes(decrypted)
    }
}

fn sodium_init() -> Result<()> {
    sodiumoxide::init().map_err(|_| InternalError::InternalInvariantFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::box_;

    #[test]
    fn test_export_import_keyshare() {
        // Initialize sodiumoxide library
        sodium_init().unwrap();

        // Generate key pairs for the sender and receiver
        let (sender_pk, sender_sk) = box_::gen_keypair();
        let (receiver_pk, receiver_sk) = box_::gen_keypair();

        // Create a random KeySharePrivate
        let mut rng = rand::thread_rng();
        let key_share = KeySharePrivate::random(&mut rng);

        // Export the key share
        let encrypted = KeyShareEncrypted::export_keyshare(&key_share, &receiver_pk, &sender_sk)
            .expect("Failed to export key share");

        // Import the key share
        let decrypted = KeyShareEncrypted::import_keyshare(&encrypted, &sender_pk, &receiver_sk)
            .expect("Failed to import key share");

        // Check that the decrypted key share matches the original
        assert_eq!(key_share, decrypted);
    }

    #[test]
    fn test_failed_import_invalid_nonce() {
        // Initialize sodiumoxide library
        sodium_init().unwrap();

        // Generate key pairs for the sender and receiver
        let (sender_pk, sender_sk) = box_::gen_keypair();
        let (receiver_pk, receiver_sk) = box_::gen_keypair();

        // Create a random KeySharePrivate
        let mut rng = rand::thread_rng();
        let key_share = KeySharePrivate::random(&mut rng);

        // Export the key share
        let mut encrypted =
            KeyShareEncrypted::export_keyshare(&key_share, &receiver_pk, &sender_sk)
                .expect("Failed to export key share");

        // Tamper with the nonce to invalidate it
        encrypted.0[0] ^= 0xff;

        // Attempt to import the key share (should fail)
        let result = KeyShareEncrypted::import_keyshare(&encrypted, &sender_pk, &receiver_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_failed_import_invalid_ciphertext() {
        // Initialize sodiumoxide library
        sodium_init().unwrap();

        // Generate key pairs for the sender and receiver
        let (sender_pk, sender_sk) = box_::gen_keypair();
        let (receiver_pk, receiver_sk) = box_::gen_keypair();

        // Create a random KeySharePrivate
        let mut rng = rand::thread_rng();
        let key_share = KeySharePrivate::random(&mut rng);

        // Export the key share
        let mut encrypted =
            KeyShareEncrypted::export_keyshare(&key_share, &receiver_pk, &sender_sk)
                .expect("Failed to export key share");

        // Tamper with the ciphertext to invalidate it
        encrypted.0[box_::NONCEBYTES] ^= 0xff;

        // Attempt to import the key share (should fail)
        let result = KeyShareEncrypted::import_keyshare(&encrypted, &sender_pk, &receiver_sk);
        assert!(result.is_err());
    }
}
