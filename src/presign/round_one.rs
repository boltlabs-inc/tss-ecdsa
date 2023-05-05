// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::info::AuxInfoPublic,
    errors::Result,
    messages::{Message, MessageType, PresignMessageType},
    paillier::{Ciphertext, EncryptionKey, Nonce},
    ring_pedersen::VerifiedRingPedersen,
    zkp::{pienc::PiEncProof, Proof, ProofContext},
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
    /// Verify the `𝚷[enc]` proof that the prover knows the plaintext
    /// associated with `ct`.
    fn verify(
        &self,
        context: &impl ProofContext,
        verifier_setup_params: &VerifiedRingPedersen,
        prover_pk: EncryptionKey,
        ct: Ciphertext,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"PiEncProof");
        let input =
            crate::zkp::pienc::PiEncInput::new(verifier_setup_params.clone(), prover_pk, ct);
        self.proof.verify(&input, context, &mut transcript)
    }

    /// Validate that [`Message`] is a valid proof that the [`PublicBroadcast`]
    /// parameters are correctly constructed.
    ///
    /// The `verifier_auxinfo_public` argument denotes the [`AuxInfoPublic`]
    /// type of the party validating the message, and the
    /// `prover_auxinfo_public` argument denotes the [`AuxInfoPublic`] type of
    /// the party providing the proof.
    pub(crate) fn validate_message(
        message: &Message,
        context: &impl ProofContext,
        verifier_auxinfo_public: &AuxInfoPublic,
        prover_auxinfo_public: &AuxInfoPublic,
        broadcasted_params: &PublicBroadcast,
    ) -> Result<()> {
        message.check_type(MessageType::Presign(PresignMessageType::RoundOne))?;
        let round_one_public: Self = deserialize!(&message.unverified_bytes)?;

        round_one_public.verify(
            context,
            verifier_auxinfo_public.params(),
            prover_auxinfo_public.pk().clone(),
            broadcasted_params.K.clone(),
        )?;
        Ok(())
    }
}
