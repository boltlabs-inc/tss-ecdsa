// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::Result,
    utils::{k256_order, CurvePoint},
    ParticipantIdentifier,
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zeroize::ZeroizeOnDrop;

/// Private key corresponding to a given [`Participant`](crate::Participant)'s
/// [`KeySharePublic`].
///
/// # 🔒 Storage requirements
/// This type must be stored securely by the calling application.
#[derive(Clone, ZeroizeOnDrop)]
pub struct KeySharePrivate {
    x: BigNumber, // in the range [1, q)
}
impl Debug for KeySharePrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySharePrivate([redacted])")
    }
}
impl KeySharePrivate {
    /// Sample a private key share uniformly at random.
    pub(crate) fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let random_bn = BigNumber::from_rng(&k256_order(), rng);
        KeySharePrivate { x: random_bn }
    }

    /// Computes the "raw" curve point corresponding to this private key.
    pub(crate) fn public_share(&self) -> Result<CurvePoint> {
        CurvePoint::GENERATOR.multiply_by_scalar(&self.x)
    }
}

impl AsRef<BigNumber> for KeySharePrivate {
    /// Get the private key share.
    fn as_ref(&self) -> &BigNumber {
        &self.x
    }
}

/// A [`CurvePoint`] representing a given [`Participant`](crate::Participant)'s
/// public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySharePublic {
    participant: ParticipantIdentifier,
    X: CurvePoint,
}

impl KeySharePublic {
    pub(crate) fn new(participant: ParticipantIdentifier, share: CurvePoint) -> Self {
        Self {
            participant,
            X: share,
        }
    }

    /// Get the ID of the participant who claims to hold the private share
    /// corresponding to this public key share.
    pub fn participant(&self) -> ParticipantIdentifier {
        self.participant
    }

    /// Generate a new [`KeySharePrivate`] and [`KeySharePublic`].
    pub fn new_keyshare<R: RngCore + CryptoRng>(
        participant: ParticipantIdentifier,
        rng: &mut R,
    ) -> Result<(KeySharePrivate, KeySharePublic)> {
        let private_share = KeySharePrivate::random(rng);
        let public_share = private_share.public_share()?;

        Ok((
            private_share,
            KeySharePublic::new(participant, public_share),
        ))
    }
}

impl AsRef<CurvePoint> for KeySharePublic {
    /// Get the public curvepoint which is the public key share.
    fn as_ref(&self) -> &CurvePoint {
        &self.X
    }
}
