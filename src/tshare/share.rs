// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{CallerError, InternalError, Result},
    paillier::{Ciphertext, DecryptionKey, EncryptionKey},
    utils::{bn_to_scalar, k256_order, scalar_to_bn, CurvePoint},
};
use k256::{elliptic_curve::Field, Scalar};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, ops::Add};
use tracing::error;
use zeroize::ZeroizeOnDrop;

/// Encrypted [`CoeffPrivate`].
#[derive(Clone, Serialize, Deserialize)]
pub struct EvalEncrypted {
    ciphertext: Ciphertext,
}

impl EvalEncrypted {
    pub fn encrypt<R: RngCore + CryptoRng>(
        share_private: &EvalPrivate,
        pk: &EncryptionKey,
        rng: &mut R,
    ) -> Result<Self> {
        if &(k256_order() * 2) >= pk.modulus() {
            error!("EvalEncrypted encryption failed, pk.modulus() is too small");
            Err(InternalError::InternalInvariantFailed)?;
        }

        let (ciphertext, _nonce) = pk
            .encrypt(rng, &scalar_to_bn(&share_private.x))
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        Ok(EvalEncrypted { ciphertext })
    }

    pub fn decrypt(&self, dk: &DecryptionKey) -> Result<EvalPrivate> {
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
        Ok(EvalPrivate {
            x: bn_to_scalar(&x).unwrap(),
        })
    }
}

/// Private coefficient share.
#[derive(Clone, ZeroizeOnDrop, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoeffPrivate {
    /// A BigNumber element in the range [1, q) representing a polynomial
    /// coefficient
    pub x: Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalPrivate {
    /// A BigNumber element in the range [1, q) representing a polynomial
    /// coefficient
    pub x: Scalar,
}

/// Implement addition operation for `EvalPrivate`.
impl Add<&EvalPrivate> for EvalPrivate {
    type Output = Self;

    fn add(self, rhs: &EvalPrivate) -> Self::Output {
        EvalPrivate {
            x: self.x + rhs.x,
        }
    }
}

impl EvalPrivate {
    pub fn new(x: Scalar) -> Self {
        EvalPrivate { x }
    }
}

impl Debug for CoeffPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CoeffPrivate([redacted])")
    }
}

/// Represents a coefficient of a polynomial.
/// Coefficients and Evaluations are represented as curve scalars.
/// The input shares are interpreted as coefficients, while the output shares
/// are interpreted as evaluations.
impl CoeffPrivate {
    /// Sample a private key share uniformly at random.
    pub(crate) fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let random_bn = Scalar::random(rng);
        CoeffPrivate { x: random_bn }
    }

    /// Computes the "raw" curve point corresponding to this private key.
    pub(crate) fn public_point(&self) -> CurvePoint {
        CurvePoint::GENERATOR.multiply_by_scalar(&self.x)
    }

    pub(crate) fn to_public(&self) -> CoeffPublic {
        CoeffPublic::new(self.public_point())
    }
}

/// Represents an evaluation of a polynomial at a given point.
/// Coefficients and Evaluations are represented as curve scalars.
/// The input shares are interpreted as coefficients, while the output shares
/// are interpreted as evaluations.
impl EvalPrivate {
    /// Sample a private key share uniformly at random.
    pub fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let random_scalar = Scalar::random(rng);
        EvalPrivate { x: random_scalar }
    }

    pub(crate) fn sum(shares: &[Self]) -> Self {
        let sum = shares.iter().fold(Scalar::ZERO, |sum, o| sum + o.x);
        EvalPrivate { x: sum }
    }

    pub(crate) fn public_point(&self) -> CurvePoint {
        CurvePoint::GENERATOR.multiply_by_scalar(&self.x)
    }
}

impl AsRef<Scalar> for CoeffPrivate {
    /// Get the coeff as a number.
    fn as_ref(&self) -> &Scalar {
        &self.x
    }
}

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
        rng: &mut R,
    ) -> Result<(CoeffPrivate, CoeffPublic)> {
        let private_share = CoeffPrivate::random(rng);
        let public_share = private_share.to_public();
        Ok((private_share, public_share))
    }
}

impl AsRef<CurvePoint> for CoeffPublic {
    /// Get the coeff as a curve point.
    fn as_ref(&self) -> &CurvePoint {
        &self.X
    }
}

impl Add<&CoeffPublic> for CoeffPublic {
    type Output = Self;

    fn add(self, rhs: &CoeffPublic) -> Self::Output {
        CoeffPublic { X: self.X + rhs.X }
    }
}

/// A curve point representing a given [`Participant`](crate::Participant)'s
/// public evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalPublic {
    X: CurvePoint,
}

impl EvalPublic {
    /// Wrap a curve point as a public evaluation.
    pub(crate) fn new(X: CurvePoint) -> Self {
        Self { X }
    }
}

impl AsRef<CurvePoint> for EvalPublic {
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
        utils::{bn_to_scalar, k256_order, testing::init_testing},
        ParticipantIdentifier,
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
        let coeff = EvalPrivate::random(rng);
        let encrypted = EvalEncrypted::encrypt(&coeff, &pk, rng).expect("encryption failed");
        let decrypted = encrypted.decrypt(&dk).expect("decryption failed");

        assert_eq!(decrypted, coeff);
    }

    #[test]
    fn coeff_decrypt_unexpected() {
        let (mut rng, pk, dk) = setup();
        let rng = &mut rng;

        // Encrypt unexpected shares.
        {
            let x = &(-BigNumber::one());
            let share = EvalPrivate {
                x: bn_to_scalar(x).expect("Failed to convert to scalar"),
            };
            let encrypted = EvalEncrypted::encrypt(&share, &pk, rng).expect("encryption failed");
            // Decryption reports an error.
            let decrypt_result = encrypted.decrypt(&dk);
            assert!(decrypt_result.is_ok());
        }
        // Encrypt zero returns an error in decryption.
        for x in [BigNumber::zero(), k256_order()].iter() {
            let share = EvalPrivate {
                x: bn_to_scalar(x).expect("Failed to convert to scalar"),
            };
            let encrypted = EvalEncrypted::encrypt(&share, &pk, rng).expect("encryption failed");
            // Decryption reports an error.
            let decrypt_result = encrypted.decrypt(&dk);
            assert!(decrypt_result.is_err());
        }
    }
}
