// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{CallerError, InternalError, Result},
    keygen::{KeySharePrivate, KeySharePublic},
    paillier::{Ciphertext, DecryptionKey, EncryptionKey},
    utils::{k256_order, CurvePoint},
    ParticipantIdentifier,
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use zeroize::ZeroizeOnDrop;

/// Encrypted [`CoeffPrivate`].
#[derive(Clone, Serialize, Deserialize)]
pub struct EvalEncrypted {
    ciphertext: Ciphertext,
}

impl EvalEncrypted {
    pub fn encrypt<R: RngCore + CryptoRng>(
        share_private: &CoeffPrivate,
        pk: &EncryptionKey,
        rng: &mut R,
    ) -> Result<Self> {
        if &(k256_order() * 2) >= pk.modulus() {
            error!("EvalEncrypted encryption failed, pk.modulus() is too small");
            Err(InternalError::InternalInvariantFailed)?;
        }

        let (ciphertext, _nonce) = pk
            .encrypt(rng, &share_private.x)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        Ok(EvalEncrypted { ciphertext })
    }

    pub fn decrypt(&self, dk: &DecryptionKey) -> Result<CoeffPrivate> {
        let x = dk.decrypt(&self.ciphertext).map_err(|_| {
            error!("EvalEncrypted decryption failed, ciphertext out of range",);
            CallerError::DeserializationFailed
        })?;
        if x >= k256_order() || x < BigNumber::one() {
            error!(
                "EvalEncrypted decryption failed, plaintext out of range (x={})",
                x
            );
            Err(CallerError::DeserializationFailed)?;
        }
        Ok(CoeffPrivate { x })
    }
}

/// Private coefficient share.
#[derive(Clone, ZeroizeOnDrop, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoeffPrivate {
    pub x: BigNumber, // in the range [1, q)
}

impl Debug for CoeffPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CoeffPrivate([redacted])")
    }
}

// TODO: remove unused methods.
impl CoeffPrivate {
    /// Sample a private key share uniformly at random.
    pub(crate) fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let random_bn = BigNumber::from_rng(&k256_order(), rng);
        CoeffPrivate { x: random_bn }
    }

    pub(crate) fn sum(shares: &[Self]) -> Self {
        let sum = shares
            .iter()
            .fold(BigNumber::zero(), |sum, o| sum + o.x.clone())
            .nmod(&k256_order());
        CoeffPrivate { x: sum }
    }

    // TODO: Introduce a dedicated Output for tshare,
    // implement tshare::Output::public_key(),
    // and remove this conversion.
    pub fn to_keyshare(&self) -> KeySharePrivate {
        KeySharePrivate::from_bigint(&self.x)
    }

    /// Computes the "raw" curve point corresponding to this private key.
    pub(crate) fn public_point(&self) -> Result<CurvePoint> {
        CurvePoint::GENERATOR.multiply_by_bignum(&self.x)
    }

    pub(crate) fn to_public(&self, participant: ParticipantIdentifier) -> Result<CoeffPublic> {
        Ok(CoeffPublic::new(self.public_point()?))
    }
}

impl AsRef<BigNumber> for CoeffPrivate {
    /// Get the coeff as a number.
    fn as_ref(&self) -> &BigNumber {
        &self.x
    }
}

// TODO: remove unused methods.
/// A curve point representing a given [`Participant`](crate::Participant)'s
/// public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoeffPublic {
    X: CurvePoint,
}

impl CoeffPublic {
    /// Wrap a curve point as a public coeff.
    pub(crate) fn new(X: CurvePoint) -> Self {
        Self { X }
    }

    /// Generate a new [`CoeffPrivate`] and [`CoeffPublic`].
    pub(crate) fn new_pair<R: RngCore + CryptoRng>(
        participant: ParticipantIdentifier,
        rng: &mut R,
    ) -> Result<(CoeffPrivate, CoeffPublic)> {
        let private_share = CoeffPrivate::random(rng);
        let public_share = private_share.to_public(participant)?;
        Ok((private_share, public_share))
    }

    // TODO: Introduce a dedicated Output for tshare, and remove this conversion.
    pub fn to_keyshare(&self, i: usize) -> KeySharePublic {
        KeySharePublic::new(ParticipantIdentifier::from_u128(i as u128), self.X)
    }
}

impl AsRef<CurvePoint> for CoeffPublic {
    /// Get the coeff as a curve point.
    fn as_ref(&self) -> &CurvePoint {
        &self.X
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auxinfo,
        utils::{k256_order, testing::init_testing},
    };
    use rand::rngs::StdRng;

    /// Generate an encryption key pair.
    fn setup() -> (StdRng, EncryptionKey, DecryptionKey) {
        let mut rng = init_testing();
        let pid = ParticipantIdentifier::random(&mut rng);
        let auxinfo = auxinfo::Output::simulate(&[pid], &mut rng);
        let dk = auxinfo.private_auxinfo().decryption_key();
        let pk = auxinfo.find_public(pid).unwrap().pk();
        assert!(
            &(k256_order() * 2) < pk.modulus(),
            "the Paillier modulus is supposed to be much larger than the k256 order"
        );
        (rng, pk.clone(), dk.clone())
    }

    #[test]
    fn coeff_encryption_works() {
        let (mut rng, pk, dk) = setup();
        let rng = &mut rng;

        // Encryption round-trip.
        let coeff = CoeffPrivate::random(rng);
        let encrypted = EvalEncrypted::encrypt(&coeff, &pk, rng).expect("encryption failed");
        let decrypted = encrypted.decrypt(&dk).expect("decryption failed");

        assert_eq!(decrypted, coeff);
    }

    #[test]
    fn coeff_decrypt_out_of_range() {
        let (mut rng, pk, dk) = setup();
        let rng = &mut rng;

        // Encrypt invalid shares.
        for x in [BigNumber::zero(), -BigNumber::one(), k256_order()].iter() {
            let share = CoeffPrivate { x: x.clone() };
            let encrypted = EvalEncrypted::encrypt(&share, &pk, rng).expect("encryption failed");
            // Decryption reports an error.
            let decrypt_result = encrypted.decrypt(&dk);
            assert!(decrypt_result.is_err());
        }
    }
}
