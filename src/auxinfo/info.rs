// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::fmt::Debug;

use crate::{
    errors::{InternalError, Result},
    paillier::{DecryptionKey, EncryptionKey},
    ring_pedersen::VerifiedRingPedersen,
    ParticipantIdentifier,
};
use k256::elliptic_curve::zeroize::ZeroizeOnDrop;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use tracing::{error, instrument};

/// The private key corresponding to a given Participant's [`AuxInfoPublic`].
///
/// TODO #169: Let's be more careful about allowing `Clone`, `Serialize`, etc.
/// here due to this being sensitive data.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct AuxInfoPrivate {
    decryption_key: DecryptionKey,
}

impl AuxInfoPrivate {
    #[cfg(test)]
    pub fn encryption_key(&self) -> EncryptionKey {
        self.decryption_key.encryption_key()
    }

    pub fn decryption_key(&self) -> &DecryptionKey {
        &self.decryption_key
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
            .field("decryption key", &"[redacted]")
            .finish()
    }
}

/// The public Auxilary Information corresponding to a given Participant.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct AuxInfoPublic {
    participant: ParticipantIdentifier,
    pk: EncryptionKey,
    params: VerifiedRingPedersen,
}

impl AuxInfoPublic {
    pub(crate) fn new(
        participant: ParticipantIdentifier,
        encryption_key: EncryptionKey,
        params: VerifiedRingPedersen,
    ) -> Result<Self> {
        let public = Self {
            participant,
            pk: encryption_key,
            params,
        };
        public.verify()?;
        Ok(public)
    }

    pub(crate) fn pk(&self) -> &EncryptionKey {
        &self.pk
    }

    pub(crate) fn params(&self) -> &VerifiedRingPedersen {
        &self.params
    }

    pub(crate) fn participant(&self) -> &ParticipantIdentifier {
        &self.participant
    }

    /// Verifies that the public key's modulus matches the ZKSetupParameters
    /// modulus N, and that the parameters have appropriate s and t values.
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn verify(&self) -> Result<()> {
        if self.pk.modulus() != self.params.scheme().modulus() {
            error!("Mismatch between public key modulus and setup parameters modulus");
            return Err(InternalError::Serialization);
        }
        self.params.verify()
    }
}

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct AuxInfoWitnesses {
    pub(crate) p: BigNumber,
    pub(crate) q: BigNumber,
}
