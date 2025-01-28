//! Module to export and import key shares, with encryption in transit.

use crate::{curve::CurveTrait, errors::Result, keygen::KeySharePrivate};

mod pke;
pub use pke::Pke;

mod sodium;
pub use sodium::SodiumPke;

/// Struct for handling the export and import of KeySharePrivate
#[derive(Clone, Debug)]
pub struct KeyShareEncrypted(Vec<u8>);

impl KeyShareEncrypted {
    /// Build a new `KeyShareEncrypted` from ciphertext bytes.
    pub fn from_vec(encrypted: Vec<u8>) -> Self {
        Self(encrypted)
    }

    /// Get the ciphertext bytes from a `KeyShareEncrypted`.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

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
    /// use tss_ecdsa::curve::TestCurve;
    /// use sodiumoxide::crypto::box_;
    ///
    /// sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    /// let (sender_pk, sender_sk) = box_::gen_keypair();
    /// let (receiver_pk, receiver_sk) = box_::gen_keypair();
    /// let mut rng = rand::thread_rng();
    /// let key_share = KeySharePrivate::<TestCurve>::random(&mut rng);
    ///
    /// let exported = KeyShareEncrypted::export_keyshare::<SodiumPke, TestCurve>(&key_share, &receiver_pk, &sender_sk)
    ///     .expect("Failed to export keyshare");
    /// let exported_bytes = exported.into_vec();
    ///
    /// let to_import = KeyShareEncrypted::from_vec(exported_bytes);
    /// let imported = to_import.import_keyshare::<SodiumPke, TestCurve>(&sender_pk, &receiver_sk)
    ///     .expect("Failed to import keyshare");
    ///
    /// assert_eq!(imported, key_share);
    /// ```
    pub fn export_keyshare<T: Pke, C: CurveTrait>(
        key_share: &KeySharePrivate<C>,
        receiver_pk: &T::PublicKey,
        sender_sk: &T::SecretKey,
    ) -> Result<Self> {
        let serialized = key_share.clone().into_bytes();
        let encrypted_data = T::encrypt(&serialized, receiver_pk, sender_sk)?;
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
    pub fn import_keyshare<T: Pke, C: CurveTrait>(
        &self,
        sender_pk: &T::PublicKey,
        receiver_sk: &T::SecretKey,
    ) -> Result<KeySharePrivate<C>> {
        let decrypted_data = T::decrypt(&self.0, sender_pk, receiver_sk)?;
        KeySharePrivate::try_from_bytes(decrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use crate::curve::TestCurve;

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
        let mut encrypted = KeyShareEncrypted::export_keyshare::<SodiumPke, TestCurve>(
            &key_share,
            &receiver_pk,
            &sender_sk,
        )
        .expect("Failed to export key share");

        // Tamper with the nonce to invalidate it
        encrypted.0[0] ^= 0xff;

        // Attempt to import the key share (should fail)
        let result = KeyShareEncrypted::import_keyshare::<SodiumPke, TestCurve>(
            &encrypted,
            &sender_pk,
            &receiver_sk,
        );
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
        let mut encrypted = KeyShareEncrypted::export_keyshare::<SodiumPke, TestCurve>(
            &key_share,
            &receiver_pk,
            &sender_sk,
        )
        .expect("Failed to export key share");

        // Tamper with the ciphertext to invalidate it
        encrypted.0[box_::NONCEBYTES] ^= 0xff;

        // Attempt to import the key share (should fail)
        let result = KeyShareEncrypted::import_keyshare::<SodiumPke, TestCurve>(
            &encrypted,
            &sender_pk,
            &receiver_sk,
        );
        assert!(result.is_err());
    }
}
