use crate::errors::Result;

/// Trait for public-key encryption of exported key shares.
pub trait Pke {
    /// Type for public keys
    type PublicKey;
    /// Type for secret keys
    type SecretKey;

    /// Encrypt a plaintext using the public key of the receiver and the secret
    /// key of the sender
    fn encrypt(
        plaintext: &[u8],
        receiver_pk: &Self::PublicKey,
        sender_sk: &Self::SecretKey,
    ) -> Result<Vec<u8>>;

    /// Decrypt a ciphertext using the public key of the sender and the secret
    /// key of the receiver
    fn decrypt(
        ciphertext: &[u8],
        sender_pk: &Self::PublicKey,
        receiver_sk: &Self::SecretKey,
    ) -> Result<Vec<u8>>;
}
