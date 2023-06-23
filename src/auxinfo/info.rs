// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{CallerError, InternalError, Result},
    paillier::{DecryptionKey, EncryptionKey},
    ring_pedersen::VerifiedRingPedersen,
    zkp::ProofContext,
    ParticipantIdentifier,
};
use k256::elliptic_curve::zeroize::ZeroizeOnDrop;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::{error, instrument};
/// Private auxiliary information for a specific
/// [`Participant`](crate::Participant).
///
/// This includes a Paillier decryption key; there should be a corresponding
/// [`AuxInfoPublic`] with the encryption key and ring-Pedersen commitment
/// parameters formed with the same modulus.
///
/// # 🔒 Storage requirements
/// This type must be stored securely by the calling application.
///
/// Note: this doesn't implement [`ZeroizeOnDrop`] but all of its internal types
/// do.
#[derive(Clone, PartialEq, Eq)]
pub struct AuxInfoPrivate {
    /// The participant's Paillier private key.
    decryption_key: DecryptionKey,
}

const AUXINFO_TAG: &[u8] = b"AuxInfoPrivate";
// Length of the length field for auxinfo serialization.
const AUXINFO_LEN: usize = 8;

impl AuxInfoPrivate {
    pub(crate) fn encryption_key(&self) -> EncryptionKey {
        self.decryption_key.encryption_key()
    }

    pub(crate) fn decryption_key(&self) -> &DecryptionKey {
        &self.decryption_key
    }

    /// Convert private material into bytes.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. The output of this function should be handled with care.
    pub fn into_bytes(self) -> Vec<u8> {
        // Format:
        // AUXINFO_TAG | key_len in bytes | key
        //             | ---8 bytes------ | --key_len bytes---

        let key = self.decryption_key.into_bytes();
        let key_len = key.len().to_le_bytes();

        [AUXINFO_TAG, &key_len, &key].concat()
    }

    /// Convert bytes into private material.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. Do not use this method to create arbitrary instances of
    /// [`AuxInfoPrivate`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Expected format:
        // AUXINFO_TAG | key_len in bytes | key
        //             | ---8 bytes------ | --key_len bytes---

        // Check the tag.
        if bytes.len() < AUXINFO_TAG.len() {
            error!("Failed to deserialize `AuxInfoPrivate` due to invalid tag");
            Err(CallerError::DeserializationFailed)?
        }
        // This panics if the parameter is larger than the length, but we check above so
        // it's okay.
        let (actual_tag, bytes) = bytes.split_at(AUXINFO_TAG.len());
        let tag_content_is_correct = actual_tag == AUXINFO_TAG;
        if !tag_content_is_correct {
            error!("Failed to deserialize `AuxInfoPrivate` due to invalid tag");
            Err(CallerError::DeserializationFailed)?
        }

        // Check the key len
        if bytes.len() < AUXINFO_LEN {
            error!("Failed to deserialize `AuxInfoPrivate` due to invalid length field");
            Err(CallerError::DeserializationFailed)?
        }
        let (key_len, key_bytes) = bytes.split_at(AUXINFO_LEN);
        let fixed_size_len: [u8; 8] = key_len.try_into().map_err(|_| {
            error!("Failed to convert byte array (should always work because we defined it to be exactly 8 bytes)");
            InternalError::InternalInvariantFailed
        })?;
        if usize::from_le_bytes(fixed_size_len) != key_bytes.len() {
            error!("Failed to deserialize `AuxInfoPrivate` due to invalid length field");
            Err(CallerError::DeserializationFailed)?
        }

        // Check the key
        let decryption_key = DecryptionKey::try_from_bytes(key_bytes.to_vec())
            .map_err(|_| CallerError::DeserializationFailed)?;

        Ok(Self { decryption_key })
    }
}

impl From<DecryptionKey> for AuxInfoPrivate {
    fn from(decryption_key: DecryptionKey) -> Self {
        Self { decryption_key }
    }
}

impl Debug for AuxInfoPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxInfoPrivate")
            .field("decryption_key", &"[redacted]")
            .finish()
    }
}

/// The public auxilary information for a specific
/// [`Participant`](crate::Participant).
///
/// This includes a Paillier encryption key and corresponding ring-Pedersen
/// commitment parameters.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AuxInfoPublic {
    /// The participant's identifier.
    participant: ParticipantIdentifier,
    /// The participant's Paillier public key.
    pk: EncryptionKey,
    /// The participant's (verified) ring-Pedersen parameters.
    params: VerifiedRingPedersen,
}

impl AuxInfoPublic {
    pub(crate) fn new(
        context: &impl ProofContext,
        participant: ParticipantIdentifier,
        encryption_key: EncryptionKey,
        params: VerifiedRingPedersen,
    ) -> Result<Self> {
        let public = Self {
            participant,
            pk: encryption_key,
            params,
        };
        public.verify(context)?;
        Ok(public)
    }

    pub(crate) fn pk(&self) -> &EncryptionKey {
        &self.pk
    }

    pub(crate) fn params(&self) -> &VerifiedRingPedersen {
        &self.params
    }

    pub(crate) fn participant(&self) -> ParticipantIdentifier {
        self.participant
    }

    /// Verifies that the public key's modulus matches the ZKSetupParameters
    /// modulus N, and that the parameters have appropriate s and t values.
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn verify(&self, context: &impl ProofContext) -> Result<()> {
        if self.pk.modulus() != self.params.scheme().modulus() {
            error!("Mismatch between public key modulus and setup parameters modulus");
            return Err(InternalError::Serialization);
        }
        self.params.verify(context)
    }
}

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct AuxInfoWitnesses {
    pub(crate) p: BigNumber,
    pub(crate) q: BigNumber,
}

impl Debug for AuxInfoWitnesses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxInfoWitnesses")
            .field("p", &"[redacted]")
            .field("q", &"[redacted]")
            .finish()
    }
}
