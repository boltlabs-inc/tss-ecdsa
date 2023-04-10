// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::info::AuxInfoPublic,
    errors::{InternalError, Result},
    messages::{Message, MessageType, PresignMessageType},
    paillier::{Ciphertext, EncryptionKey, Nonce},
    ring_pedersen::VerifiedRingPedersen,
    zkp::{pienc::PiEncProof, Proof, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use zeroize::ZeroizeOnDrop;

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Public {
    pub proof: PiEncProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublicBroadcast {
    pub K: Ciphertext,
    pub G: Ciphertext,
}

impl Public {
    /// Verify M(vrfy, Π^enc_i, (ssid, j), (I_ε, K_j), ψ_{i,j}) = 1
    /// setup_params should be the receiving party's setup parameters
    /// the modulus N should be the sending party's modulus N
    fn verify(
        &self,
        context: &impl ProofContext,
        receiver_setup_params: &VerifiedRingPedersen,
        sender_pk: EncryptionKey,
        K: Ciphertext,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"PiEncProof");
        let input = crate::zkp::pienc::PiEncInput::new(receiver_setup_params.clone(), sender_pk, K);
        self.proof.verify(&input, context, &mut transcript)
    }

    pub(crate) fn from_message(
        message: &Message,
        context: &impl ProofContext,
        receiver_keygen_public: &AuxInfoPublic,
        sender_keygen_public: &AuxInfoPublic,
        broadcasted_params: &PublicBroadcast,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Presign(PresignMessageType::RoundOne) {
            error!(
                "Encountered unexpected MessageType. Expected {:?}, Got {:?}",
                MessageType::Presign(PresignMessageType::RoundOne),
                message.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }
        let round_one_public: Self = deserialize!(&message.unverified_bytes)?;

        round_one_public.verify(
            context,
            receiver_keygen_public.params(),
            sender_keygen_public.pk().clone(),
            broadcasted_params.K.clone(),
        )?;
        Ok(round_one_public)
    }
}
