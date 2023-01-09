// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::{InternalError, Result};
use crate::parameters::PRIME_BITS;
use crate::utils::{random_bn_in_z_star, CRYPTOGRAPHIC_RETRY_MAX};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Paillier-specific errors
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaillierError {
    #[error("Failed to create a Paillier decryption key from inputs")]
    CouldNotCreateKey,
    #[error("The inputs to a homomorphic operation on a Paillier ciphertext were malformed")]
    InvalidOperation,
    #[error("The attemped decryption of a Pailler ciphertext failed")]
    DecryptionFailed,

    #[cfg(test)]
    #[error("No pre-generated primes with size {0}")]
    NoPregeneratedPrimes(usize),
}

/// TODO: Remove this once `InternalError` is instantiated with thiserror.
impl From<PaillierError> for InternalError {
    fn from(err: PaillierError) -> Self {
        InternalError::PaillierError(err)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierCiphertext(pub(crate) BigNumber);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierEncryptionKey(pub(crate) libpaillier::EncryptionKey);

impl PaillierEncryptionKey {
    pub(crate) fn n(&self) -> &BigNumber {
        self.0.n()
    }

    pub(crate) fn encrypt<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        x: &BigNumber,
    ) -> Result<(BigNumber, BigNumber)> {
        let nonce = random_bn_in_z_star(rng, self.0.n())?;

        let one = BigNumber::one();
        let base = one + self.n();
        let a = base.modpow(x, self.0.nn());
        let b = nonce.modpow(self.n(), self.0.nn());
        let c = a.modmul(&b, self.0.nn());
        Ok((c, nonce))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierDecryptionKey(libpaillier::DecryptionKey);

impl PaillierDecryptionKey {
    pub(crate) fn decrypt(&self, c: &BigNumber) -> Result<Vec<u8>> {
        Ok(self.0.decrypt(c).ok_or(PaillierError::DecryptionFailed)?)
    }

    /// Generate a new [`PaillierDecryptionKey`] and its factors.
    ///
    /// The factors `p` and `q` are `PRIME_BITS`-long safe primes, and the resulting
    /// modulus is `2 * PRIME_BITS` long.
    pub(crate) fn new(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Self, BigNumber, BigNumber)> {
        // Generate a pair of safe primes that are `PRIME_BITS` long and return them if
        // their product is `2 * PRIME_BITS` long (otherwise return `None`).
        let generate_prime_pair = || -> Result<(BigNumber, BigNumber)> {
            // As generating safe primes can be computationally expensive (> one minute per prime
            // in github CI), we read precomputed ones from a file (but only in tests!)
            #[cfg(not(test))]
            let (p, q) = (
                prime_gen::get_random_safe_prime(rng),
                prime_gen::get_random_safe_prime(rng),
            );
            #[cfg(test)]
            let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(rng)?;

            if p.bit_length() == PRIME_BITS
                && q.bit_length() == PRIME_BITS
                && (&p * &q).bit_length() == 2 * PRIME_BITS
            {
                Ok((p, q))
            } else {
                Err(PaillierError::CouldNotCreateKey)?
            }
        };

        // A Paillier decryption key is the product of the two primes, but sometimes two n/2-bit
        // primes can produce an n-1 bit modulus. Allow some (lazily evaluated) retries to handle
        // that error.
        let (p, q) = std::iter::repeat_with(generate_prime_pair)
            .take(CRYPTOGRAPHIC_RETRY_MAX)
            .find(|result| result.is_ok())
            // We hit the maximum number of retries without getting an acceptable pair.
            // We should never hit the second `?` unless `find` breaks.
            .ok_or(InternalError::RetryFailed)??;

        let decryption_key = PaillierDecryptionKey(
            libpaillier::DecryptionKey::with_primes(&p, &q)
                .ok_or(PaillierError::CouldNotCreateKey)?,
        );

        // Double check that the modulus is the correct size.
        if decryption_key.0.n().bit_length() == 2 * PRIME_BITS {
            Ok((decryption_key, p, q))
        } else {
            Err(PaillierError::CouldNotCreateKey)?
        }
    }

    /// Retrieve the public [`PaillierEncryptionKey`] corresponding to this secret
    /// [`PaillierDecryptionKey`].
    pub fn encryption_key(&self) -> PaillierEncryptionKey {
        PaillierEncryptionKey(libpaillier::EncryptionKey::from(&self.0))
    }
}

// Safe prime generation functions for production and testing.
pub(crate) mod prime_gen {
    use super::*;
    #[cfg(test)]
    use rand::Rng;
    use rand::{CryptoRng, RngCore};

    /// Sample a safe prime with length `PRIME_BITS` at random.
    pub(crate) fn get_random_safe_prime<R: RngCore + CryptoRng>(rng: &mut R) -> BigNumber {
        BigNumber::safe_prime_from_rng(PRIME_BITS, rng)
    }

    #[cfg(test)]
    lazy_static::lazy_static! {
        /// List of `PRIME_BITS`-length safe primes, generated _insecurely_.
        static ref POOL_OF_PRIMES: Vec<BigNumber> = get_safe_primes_from_file();
    }

    /// Load a set of pre-generated safe primes from a file for testing efficiency.
    #[cfg(test)]
    fn get_safe_primes_from_file() -> Vec<BigNumber> {
        match PRIME_BITS {
            // The list of 512-bit primes includes safe primes of different lengths (511-514), so
            // we filter out any that aren't exactly 512.
            512 => crate::safe_primes_512::SAFE_PRIMES
                .iter()
                .map(|s| BigNumber::from_slice(hex::decode(s).unwrap()))
                .filter(|prime| prime.bit_length() == PRIME_BITS)
                .collect(),

            // This is the recommended `PRIME_BITS` value.
            1024 => crate::safe_primes_1024::SAFE_PRIMES
                .iter()
                .map(|s| BigNumber::from_slice(hex::decode(s).unwrap()))
                .collect(),

            _ => Vec::new(),
        }
    }

    /// Sample a safe prime from a precompiled list. For testing purposes only!!
    ///
    /// Only returns `None` if there aren't any primes in the pool.
    #[cfg(test)]
    pub(crate) fn try_get_prime_from_pool_insecure<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<BigNumber> {
        if POOL_OF_PRIMES.len() == 0 {
            Err(PaillierError::NoPregeneratedPrimes(PRIME_BITS))?;
        }
        Ok(POOL_OF_PRIMES
            .get(rng.gen_range(0..POOL_OF_PRIMES.len()))
            .cloned()
            .ok_or(PaillierError::NoPregeneratedPrimes(PRIME_BITS))?)
    }

    /// Sample a pair of independent, non-matching safe primes from a precompiled list.
    /// For testing purposes only!!
    #[cfg(test)]
    pub(crate) fn get_prime_pair_from_pool_insecure<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(BigNumber, BigNumber)> {
        let p = try_get_prime_from_pool_insecure(rng)?;
        loop {
            let q = try_get_prime_from_pool_insecure(rng)?;
            if p != q {
                break Ok((p, q));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use libpaillier::unknown_order::BigNumber;

    use crate::parameters::PRIME_BITS;

    use super::{prime_gen, PaillierDecryptionKey};

    #[test]
    #[ignore = "sometimes slow in debug mode"]
    fn get_random_safe_prime_512_produces_safe_primes() {
        let mut rng = crate::utils::get_test_rng();
        let p = prime_gen::get_random_safe_prime(&mut rng);
        assert!(p.is_prime());
        let q: BigNumber = (p - 1) / 2;
        assert!(q.is_prime());
    }

    #[test]
    fn paillier_keygen_produces_good_primes() {
        let mut rng = crate::utils::get_test_rng();

        let (decryption_key, p, q) = PaillierDecryptionKey::new(&mut rng).unwrap();

        assert!(p.is_prime());
        assert!(q.is_prime());

        let safe_p: BigNumber = (&p - 1) / 2;
        assert!(safe_p.is_prime());
        let safe_q: BigNumber = (&q - 1) / 2;
        assert!(safe_q.is_prime());

        assert_eq!(p.bit_length(), PRIME_BITS);
        assert_eq!(q.bit_length(), PRIME_BITS);

        let modulus = &p * &q;
        assert_eq!(decryption_key.0.n(), &modulus);
        assert_eq!(modulus.bit_length(), 2 * PRIME_BITS);
    }

    #[test]
    #[ignore = "slow"]
    fn paillier_keygen_always_produces_good_primes() {
        for _ in 0..100 {
            paillier_keygen_produces_good_primes()
        }
    }
}
