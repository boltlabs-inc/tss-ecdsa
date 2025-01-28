// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use super::participant::ParticipantPresignContext;
use crate::{
    curve::CurveTrait,
    errors::{InternalError, Result},
    messages::{Message, MessageType, PresignMessageType},
    paillier::{Ciphertext, EncryptionKey, Nonce},
    ring_pedersen::VerifiedRingPedersen,
    zkp::{
        pienc::{PiEncInput, PiEncProof},
        Proof,
    },
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zeroize::ZeroizeOnDrop;

/// Private data used in round one of the presign protocol.
#[derive(ZeroizeOnDrop)]
pub(crate) struct Private {
    pub k: BigNumber,
    pub rho: Nonce,
    pub gamma: BigNumber,
    pub nu: Nonce,
    #[zeroize(skip)]
    pub G: Ciphertext, // Technically can be public but is only one per party
    #[zeroize(skip)]
    pub K: Ciphertext, // Technically can be public but is only one per party
}

impl Debug for Private {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("presign::round_one::Private")
            .field("k", &"[redacted]")
            .field("rho", &"[redacted]")
            .field("gamma", &"[redacted]")
            .field("nu", &"[redacted]")
            .field("G", &self.G)
            .field("K", &self.K)
            .finish()
    }
}

/// Public information produced in round one of the presign protocol.
///
/// This type implements [`TryFrom`] on [`Message`], which validates that
/// [`Message`] is a valid serialization of `Public`, but _not_ that `Public` is
/// necessarily valid (i.e., that all the components are valid with respect to
/// each other); use [`Public::verify`] to check this latter condition.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Public<C: CurveTrait> {
    #[serde(bound(deserialize = "C: CurveTrait"))]
    proof: PiEncProof<C>,
}

impl<C: CurveTrait> From<PiEncProof<C>> for Public<C> {
    fn from(proof: PiEncProof<C>) -> Self {
        Self { proof }
    }
}

/// Public information broadcast in round one of the presign protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublicBroadcast {
    pub K: Ciphertext,
    pub G: Ciphertext,
}

impl<C: CurveTrait> Public<C> {
    /// Verify the validity of [`Public`] against the prover's [`EncryptionKey`]
    /// and [`PublicBroadcast`] values.
    ///
    /// Note: The [`VerifiedRingPedersen`] value must be that of the _caller_
    /// (i.e., the verifier).
    pub(crate) fn verify(
        self,
        context: &ParticipantPresignContext<C>,
        verifier_setup_params: &VerifiedRingPedersen,
        prover_pk: &EncryptionKey,
        prover_public_broadcast: &PublicBroadcast,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"PiEncProof");
        let input = PiEncInput::new(verifier_setup_params, prover_pk, &prover_public_broadcast.K);
        self.proof.verify(input, context, &mut transcript)
    }
}

impl<C: CurveTrait> TryFrom<&Message> for Public<C> {
    type Error = InternalError;

    fn try_from(message: &Message) -> std::result::Result<Self, Self::Error> {
        message.check_type(MessageType::Presign(PresignMessageType::RoundOne))?;
        let public: Self = deserialize!(&message.unverified_bytes)?;
        Ok(public)
    }
}
