// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{CallerError, InternalError, Result},
    utils::{k256_order, CurvePoint},
    ParticipantIdentifier,
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use zeroize::ZeroizeOnDrop;

const KEYSHARE_TAG: &[u8] = b"KeySharePrivate";
/// Length of the field indicating the length of the key share.
const KEYSHARE_LEN: usize = 8;

/// Private key corresponding to a given [`Participant`](crate::Participant)'s
/// [`KeySharePublic`].
///
/// # 🔒 Storage requirements
/// This type must be stored securely by the calling application.
#[derive(Clone, ZeroizeOnDrop, PartialEq, Eq)]
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

    /// Convert private material into bytes.
    ///
    /// 🔒 This is inteded for use by the calling application for secure
    /// storage. The output of this function should be handled with care.
    pub fn into_bytes(self) -> Vec<u8> {
        // Format:
        // KEYSHARE_TAG | key_len in bytes | key (big endian bytes)
        //              | 8 bytes          | key_len bytes

        let share = self.x.to_bytes();
        let share_len = share.len().to_le_bytes();

        [KEYSHARE_TAG, &share_len, &share].concat()
    }

    /// Convert bytes into private material.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. Do not use this method to create arbitrary instances of
    /// [`KeySharePrivate`].
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Expected format:
        // KEYSHARE_TAG | key_len in bytes | key (big endian bytes)
        //              | 8 bytes          | key_len bytes

        // Check the tag.
        if bytes.len() < KEYSHARE_TAG.len() {
            error!("Failed to deserialize `KeySharePrivate`: invalid tag");
            Err(CallerError::DeserializationFailed)?
        }
        let (actual_tag, bytes) = bytes.split_at(KEYSHARE_TAG.len());
        if actual_tag != KEYSHARE_TAG {
            error!("Failed to deserialize `KeySharePrivate`: invalid tag");
            Err(CallerError::DeserializationFailed)?
        }

        // Check the share len
        if bytes.len() < KEYSHARE_LEN {
            error!("Failed to deserialize `KeySharePrivate`: invalid length field");
            Err(CallerError::DeserializationFailed)?
        }
        let (share_len, share_bytes) = bytes.split_at(KEYSHARE_LEN);
        let fixed_size_len: [u8; KEYSHARE_LEN] = share_len.try_into().map_err(|_| {
            error!("Failed to convert byte array even though we specified the size");
            InternalError::InternalInvariantFailed
        })?;

        if usize::from_le_bytes(fixed_size_len) != share_bytes.len() {
            error!("Failed to deserialize `KeySharePrivate`: invalid length field");
            Err(CallerError::DeserializationFailed)?
        }

        // Check the key share
        let share = BigNumber::from_slice(share_bytes);
        if share > k256_order() || share < BigNumber::zero() {
            error!("Failed to deserialize `KeySharePrivate`: share value out of range");
            Err(CallerError::DeserializationFailed)?
        }

        Ok(Self { x: share })
    }
}

impl AsRef<BigNumber> for KeySharePrivate {
    /// Get the private key share.
    fn as_ref(&self) -> &BigNumber {
        &self.x
    }
}

/// A curve point representing a given [`Participant`](crate::Participant)'s
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
    pub(crate) fn new_keyshare<R: RngCore + CryptoRng>(
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
