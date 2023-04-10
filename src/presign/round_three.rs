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
    presign::{
        round_one::PublicBroadcast as RoundOnePublicBroadcast,
        round_two::{Private as RoundTwoPrivate, Public as RoundTwoPublic},
    },
    zkp::{
        pilog::{CommonInput, PiLogProof},
        Proof, ProofContext,
    },
    CurvePoint,
};
use k256::Scalar;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use zeroize::ZeroizeOnDrop;

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct Private {
    pub k: BigNumber,
    pub chi: Scalar,
    #[zeroize(skip)]
    pub Gamma: CurvePoint,
    #[zeroize(skip)]
    pub delta: Scalar,
    #[zeroize(skip)]
    pub Delta: CurvePoint,
}

impl Debug for Private {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note: delta, Gamma, and Delta are all sent over the network to other
        // parties so I assume they are not actually private data.
        f.debug_struct("presign::round_three::Private")
            .field("k", &"[redacted]")
            .field("chi", &"[redacted]")
            .field("delta", &self.delta)
            .field("Gamma", &self.Gamma)
            .field("Delta", &self.Delta)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Public {
    pub delta: Scalar,
    pub Delta: CurvePoint,
    pub psi_double_prime: PiLogProof,
    /// Gamma value included for convenience
    pub Gamma: CurvePoint,
}

impl Public {
    pub(crate) fn verify(
        &self,
        context: &impl ProofContext,
        receiver_keygen_public: &AuxInfoPublic,
        sender_keygen_public: &AuxInfoPublic,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"PiLogProof");
        let psi_double_prime_input = CommonInput::new(
            sender_r1_public_broadcast.K.clone(),
            self.Delta,
            receiver_keygen_public.params().scheme().clone(),
            sender_keygen_public.pk().clone(),
            self.Gamma,
        );
        self.psi_double_prime
            .verify(&psi_double_prime_input, context, &mut transcript)?;

        Ok(())
    }

    pub(crate) fn from_message(
        message: &Message,
        context: &impl ProofContext,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Presign(PresignMessageType::RoundThree) {
            error!(
                "Encountered unexpected MessageType. Expected {:?}, Got {:?}",
                MessageType::Presign(PresignMessageType::RoundThree),
                message.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }

        let round_three_public: Self = deserialize!(&message.unverified_bytes)?;

        round_three_public.verify(
            context,
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_r1_public_broadcast,
        )?;
        Ok(round_three_public)
    }
}

/// Used to bundle the inputs passed to round_three() together
pub(crate) struct RoundThreeInput {
    pub auxinfo_public: AuxInfoPublic,
    pub r2_private: RoundTwoPrivate,
    pub r2_public: RoundTwoPublic,
}
