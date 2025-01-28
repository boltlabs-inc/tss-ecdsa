// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    curve::{CurveTrait, ScalarTrait},
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePrivate,
    paillier::{Ciphertext, DecryptionKey, EncryptionKey},
};
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
    pub fn encrypt<C: CurveTrait, R: RngCore + CryptoRng>(
        share_private: &EvalPrivate<C>,
        pk: &EncryptionKey,
        rng: &mut R,
    ) -> Result<Self> {
        if &(C::order() * 2) >= pk.modulus() {
            error!("EvalEncrypted encryption failed, pk.modulus() is too small");
            Err(InternalError::InternalInvariantFailed)?;
        }

        let (ciphertext, _nonce) = pk
            .encrypt(rng, &C::scalar_to_bn(&share_private.x))
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        Ok(EvalEncrypted { ciphertext })
    }

    pub fn decrypt<C: CurveTrait>(&self, dk: &DecryptionKey) -> Result<EvalPrivate<C>> {
        let x = dk.decrypt(&self.ciphertext).map_err(|_| {
            error!("EvalEncrypted decryption failed, ciphertext out of range",);
            CallerError::DeserializationFailed
        })?;
        if x >= C::order() || x < BigNumber::one() {
            error!(
                "EvalEncrypted decryption failed, plaintext out of range (x={})",
                x
            );
            Err(CallerError::DeserializationFailed)?;
        }
        Ok(EvalPrivate::new(C::bn_to_scalar(&x).unwrap()))
    }
}

/// Private coefficient share corresponding to some `CoeffPublic`.
#[derive(Clone, ZeroizeOnDrop, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoeffPrivate<C: CurveTrait> {
    /// A BigNumber element in the range [1, q) representing a polynomial
    /// coefficient
    pub x: C::Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalPrivate<C: CurveTrait> {
    /// A BigNumber element in the range [1, q) representing a polynomial
    /// coefficient
    pub x: C::Scalar,
}

/// Implement addition operation for `EvalPrivate`.
impl<C: CurveTrait> Add<&EvalPrivate<C>> for EvalPrivate<C> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        EvalPrivate::new(self.x.add(rhs.x))
    }
}

impl<C: CurveTrait> EvalPrivate<C> {
    pub fn new(x: C::Scalar) -> Self {
        EvalPrivate { x }
    }
}

impl<C: CurveTrait> Debug for CoeffPrivate<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CoeffPrivate([redacted])")
    }
}

impl<C: CurveTrait> TryFrom<&KeySharePrivate<C>> for CoeffPrivate<C> {
    fn try_from(share: &KeySharePrivate<C>) -> Result<Self> {
        let x = C::bn_to_scalar(share.as_ref())?;
        Ok(CoeffPrivate::<C> { x })
    }

    type Error = InternalError;
}

/// Represents a coefficient of a polynomial.
/// Coefficients and Evaluations are represented as curve scalars.
/// The input shares are interpreted as coefficients, while the output shares
/// are interpreted as evaluations.
impl<C: CurveTrait> CoeffPrivate<C> {
    /// Sample a private key share uniformly at random.
    pub(crate) fn random() -> Self {
        let random_bn = C::Scalar::random();
        CoeffPrivate { x: random_bn }
    }

    /// Computes the "raw" curve point corresponding to this private key.
    pub(crate) fn public_point(&self) -> C {
        C::GENERATOR.mul(&self.x)
    }

    pub(crate) fn to_public(&self) -> CoeffPublic<C> {
        CoeffPublic::new(self.public_point())
    }
}

/// Represents an evaluation of a polynomial at a given point.
/// Coefficients and Evaluations are represented as curve scalars.
/// The input shares are interpreted as coefficients, while the output shares
/// are interpreted as evaluations.
impl<C: CurveTrait> EvalPrivate<C> {
    /// Sample a private key share uniformly at random.
    pub fn random() -> Self {
        let random_scalar = C::Scalar::random();
        EvalPrivate::new(random_scalar)
    }

    pub(crate) fn sum(shares: &[Self]) -> Self {
        let sum = shares.iter().fold(C::Scalar::zero(), |sum, o| sum.add(o.x));
        EvalPrivate::new(sum)
    }

    pub(crate) fn public_point(&self) -> C {
        C::GENERATOR.mul(&self.x)
    }
}

impl<C: CurveTrait> AsRef<C::Scalar> for CoeffPrivate<C> {
    /// Get the coeff as a number.
    fn as_ref(&self) -> &C::Scalar {
        &self.x
    }
}

/// A curve point, primarily interpreted as hiding some
/// coefficient of known or unknown polynomial depending
/// on the context. Also describes a given [`Participant`](crate::Participant)'s
/// ECDSA public key share.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoeffPublic<C> {
    X: C,
}

impl<C: CurveTrait> CoeffPublic<C> {
    /// Wrap a curve point as a public coeff.
    pub(crate) fn new(X: C) -> Self {
        Self { X }
    }

    /// Generate a new [`CoeffPrivate`] and [`CoeffPublic`].
    pub(crate) fn new_pair() -> Result<(CoeffPrivate<C>, CoeffPublic<C>)> {
        let private_share = CoeffPrivate::random();
        let public_share = private_share.to_public();
        Ok((private_share, public_share))
    }
}

impl<C> AsRef<C> for CoeffPublic<C> {
    /// Get the coeff as a curve point.
    fn as_ref(&self) -> &C {
        &self.X
    }
}

impl<C: CurveTrait> Add<&CoeffPublic<C>> for CoeffPublic<C> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        CoeffPublic { X: self.X + rhs.X }
    }
}

/// A curve point representing a given [`Participant`](crate::Participant)'s
/// public evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalPublic<C> {
    X: C,
}

impl<C> EvalPublic<C> {
    /// Wrap a curve point as a public evaluation.
    pub(crate) fn new(X: C) -> Self {
        Self { X }
    }
}

impl<C> AsRef<C> for EvalPublic<C> {
    /// Get the coeff as a curve point.
    fn as_ref(&self) -> &C {
        &self.X
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auxinfo,
        curve::{CurveTrait, TestCurve as C},
        utils::testing::init_testing,
        ParticipantIdentifier,
    };
    use rand::rngs::StdRng;
    type EvalPrivate = super::EvalPrivate<C>;

    /// Generate an encryption key pair.
    fn setup() -> (StdRng, EncryptionKey, DecryptionKey) {
        let mut rng = init_testing();
        let pid = ParticipantIdentifier::random(&mut rng);
        let auxinfo = auxinfo::Output::simulate(&[pid], &mut rng);
        let dk = auxinfo.private_auxinfo().decryption_key();
        let pk = auxinfo.find_public(pid).unwrap().pk();
        assert!(
            &(C::order() * 2) < pk.modulus(),
            "the Paillier modulus is supposed to be much larger than the k256 order"
        );
        (rng, pk.clone(), dk.clone())
    }

    #[test]
    fn coeff_encryption_works() {
        let (mut rng, pk, dk) = setup();
        let rng = &mut rng;

        // Encryption round-trip.
        let coeff = EvalPrivate::random();
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
            let share = EvalPrivate::new(C::bn_to_scalar(x).expect("Failed to convert to scalar"));
            let encrypted = EvalEncrypted::encrypt(&share, &pk, rng).expect("encryption failed");
            // Decryption reports an error.
            let decrypt_result = encrypted.decrypt::<C>(&dk);
            assert!(decrypt_result.is_ok());
        }
        // Encrypt zero returns an error in decryption.
        for x in [BigNumber::zero(), C::order()].iter() {
            let share = EvalPrivate::new(C::bn_to_scalar(x).expect("Failed to convert to scalar"));
            let encrypted = EvalEncrypted::encrypt(&share, &pk, rng).expect("encryption failed");
            // Decryption reports an error.
            let decrypt_result = encrypted.decrypt::<C>(&dk);
            assert!(decrypt_result.is_err());
        }
    }
}
