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
#[derive(Clone, ZeroizeOnDrop, Debug)]
pub struct KeySharePrivate {
    x: BigNumber, // in the range [1, q)
}

impl KeySharePrivate {
    /// Get the private key share of the participant.
    pub fn x(&self) -> BigNumber {
        self.x.clone()
    }

    /// Set x.
    pub fn set_x(priv_share: BigNumber) -> KeySharePrivate {
        KeySharePrivate { x: priv_share }
    }

    /// Computes the "raw" curve point corresponding to this private key.
    pub(crate) fn public_share(&self) -> Result<CurvePoint> {
        CurvePoint::GENERATOR.multiply_by_scalar(&self.x)
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

    /// Get the public curvepoint which is the public key share of the
    /// participant.
    pub fn X(&self) -> CurvePoint {
        self.X
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
        let order = k256_order();
        let random_bn = BigNumber::from_rng(&order, rng);
        let private_share = KeySharePrivate::set_x(random_bn);
        /*let private_share = KeySharePrivate {
            x: BigNumber::from_rng(&order, rng),
        };*/
        let public_share = private_share.public_share()?;

        Ok((
            private_share,
            KeySharePublic::new(participant, public_share),
        ))
    }
}
