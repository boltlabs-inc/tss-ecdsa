// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{utils::CurvePoint, ParticipantIdentifier};
use libpaillier::unknown_order::BigNumber;
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
    pub(crate) x: BigNumber, // in the range [1, q)
}

impl Debug for KeySharePrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySharePrivate([redacted])")
    }
}

/// A [`CurvePoint`] representing a given [`Participant`](crate::Participant)'s
/// public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySharePublic {
    participant: ParticipantIdentifier,
    pub(crate) X: CurvePoint,
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
}
