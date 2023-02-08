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
    utils::k256_order,
    zkp::{
        pilog::{PiLogInput, PiLogProof},
        Proof,
    },
    CurvePoint,
};
use k256::Scalar;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Private {
    pub k: BigNumber,
    pub chi: Scalar,
    pub Gamma: CurvePoint,
    pub delta: Scalar,
    pub Delta: CurvePoint,
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
        receiver_keygen_public: &AuxInfoPublic,
        sender_keygen_public: &AuxInfoPublic,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"PiLogProof");
        let psi_double_prime_input = PiLogInput::new(
            &receiver_keygen_public.params,
            &k256_order(),
            &sender_keygen_public.pk,
            &sender_r1_public_broadcast.K,
            &self.Delta,
            &self.Gamma,
        );
        self.psi_double_prime
            .verify(&psi_double_prime_input, &mut transcript)?;

        Ok(())
    }

    pub(crate) fn from_message(
        message: &Message,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Presign(PresignMessageType::RoundThree) {
            return Err(InternalError::MisroutedMessage);
        }

        let round_three_public: Self = deserialize!(&message.unverified_bytes)?;

        round_three_public.verify(
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
