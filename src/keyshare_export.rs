//! Module to export and import key shares, with encryption in transit.

use crate::{errors::Result, keygen::KeySharePrivate};
use std::{marker::PhantomData, ops::Deref};

mod pke;
pub use pke::Pke;

mod sodium;
pub use sodium::SodiumPke;

/// Struct for handling the export and import of KeySharePrivate
#[derive(Clone, Debug)]
pub struct KeyShareEncrypted<T: Pke>(Vec<u8>, PhantomData<T>);

impl<T: Pke> From<Vec<u8>> for KeyShareEncrypted<T> {
    fn from(data: Vec<u8>) -> Self {
        Self(data, PhantomData)
    }
}

impl<T: Pke> From<KeyShareEncrypted<T>> for Vec<u8> {
    fn from(encrypted: KeyShareEncrypted<T>) -> Vec<u8> {
        encrypted.0
    }
}

impl<T: Pke> Deref for KeyShareEncrypted<T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Pke> KeyShareEncrypted<T> {
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
    /// use tss_ecdsa::keygen::KeySharePrivate;
    /// use tss_ecdsa::keyshare_export::{KeyShareEncrypted, SodiumPke};
    /// use sodiumoxide::crypto::box_;
    ///
    /// sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    /// let (sender_pk, sender_sk) = box_::gen_keypair();
    /// let (receiver_pk, receiver_sk) = box_::gen_keypair();
    /// let mut rng = rand::thread_rng();
    /// let key_share = KeySharePrivate::random(&mut rng);
    ///
    /// let exported = KeyShareEncrypted::<SodiumPke>::export_keyshare(&key_share, &receiver_pk, &sender_sk)
    ///     .expect("Failed to export keyshare");
    /// let exported_bytes: Vec<u8> = exported.into();
    ///
    /// let to_import = KeyShareEncrypted::<SodiumPke>::from(exported_bytes);
    /// let imported = to_import.import_keyshare(&sender_pk, &receiver_sk)
    ///     .expect("Failed to import keyshare");
    ///
    /// assert_eq!(imported, key_share);
    /// ```
    pub fn export_keyshare(
        key_share: &KeySharePrivate,
        receiver_pk: &T::PublicKey,
        sender_sk: &T::SecretKey,
    ) -> Result<Self> {
        let serialized = key_share.clone().into_bytes();
        let encrypted_data = T::encrypt(&serialized, receiver_pk, sender_sk)?;
        Ok(Self(encrypted_data, PhantomData))
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
    pub fn import_keyshare(
        &self,
        sender_pk: &T::PublicKey,
        receiver_sk: &T::SecretKey,
    ) -> Result<KeySharePrivate> {
        let decrypted_data = T::decrypt(&self.0, sender_pk, receiver_sk)?;
        KeySharePrivate::try_from_bytes(decrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::box_;

    #[test]
    fn test_failed_import_invalid_nonce_with_libsodium() {
        // Initialize sodiumoxide library
        sodiumoxide::init().unwrap();

        // Generate key pairs for the sender and receiver
        let (sender_pk, sender_sk) = box_::gen_keypair();
        let (receiver_pk, receiver_sk) = box_::gen_keypair();

        // Create a random KeySharePrivate
        let mut rng = rand::thread_rng();
        let key_share = KeySharePrivate::random(&mut rng);

        // Export the key share using the LibsodiumPke
        let mut encrypted =
            KeyShareEncrypted::<SodiumPke>::export_keyshare(&key_share, &receiver_pk, &sender_sk)
                .expect("Failed to export key share");

        // Tamper with the nonce to invalidate it
        encrypted.0[0] ^= 0xff;

        // Attempt to import the key share (should fail)
        let result =
            KeyShareEncrypted::<SodiumPke>::import_keyshare(&encrypted, &sender_pk, &receiver_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_failed_import_invalid_ciphertext_with_libsodium() {
        // Initialize sodiumoxide library
        sodiumoxide::init().unwrap();

        // Generate key pairs for the sender and receiver
        let (sender_pk, sender_sk) = box_::gen_keypair();
        let (receiver_pk, receiver_sk) = box_::gen_keypair();

        // Create a random KeySharePrivate
        let mut rng = rand::thread_rng();
        let key_share = KeySharePrivate::random(&mut rng);

        // Export the key share using the LibsodiumPke
        let mut encrypted =
            KeyShareEncrypted::<SodiumPke>::export_keyshare(&key_share, &receiver_pk, &sender_sk)
                .expect("Failed to export key share");

        // Tamper with the ciphertext to invalidate it
        encrypted.0[box_::NONCEBYTES] ^= 0xff;

        // Attempt to import the key share (should fail)
        let result =
            KeyShareEncrypted::<SodiumPke>::import_keyshare(&encrypted, &sender_pk, &receiver_sk);
        assert!(result.is_err());
    }
}
