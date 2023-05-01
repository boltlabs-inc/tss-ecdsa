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
    keygen::keyshare::KeySharePublic,
    messages::{Message, MessageType, PresignMessageType},
    paillier::Ciphertext,
    presign::round_one::{Private as RoundOnePrivate, PublicBroadcast as RoundOnePublicBroadcast},
    zkp::{
        piaffg::{PiAffgInput, PiAffgProof},
        pilog::{CommonInput, PiLogProof},
        Proof, ProofContext,
    },
    CurvePoint,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use zeroize::ZeroizeOnDrop;

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct Private {
    pub beta: BigNumber,
    pub beta_hat: BigNumber,
}

impl Debug for Private {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("presign::round_two::Private")
            .field("beta", &"[redacted]")
            .field("beta_hat", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Public {
    pub D: Ciphertext,
    pub D_hat: Ciphertext,
    pub F: Ciphertext,
    pub F_hat: Ciphertext,
    pub Gamma: CurvePoint,
    pub psi: PiAffgProof,
    pub psi_hat: PiAffgProof,
    pub psi_prime: PiLogProof,
}

impl Public {
    fn verify(
        &self,
        context: &impl ProofContext,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_keyshare_public: &KeySharePublic,
        receiver_r1_private: &RoundOnePrivate,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<()> {
        let g = CurvePoint::GENERATOR;

        // Verify the psi proof
        let psi_input = PiAffgInput::new(
            receiver_auxinfo_public.params().clone(),
            receiver_auxinfo_public.pk().clone(),
            sender_auxinfo_public.pk().clone(),
            receiver_r1_private.K.clone(),
            self.D.clone(),
            self.F.clone(),
            self.Gamma,
        );
        let mut transcript = Transcript::new(b"PiAffgProof");

        self.psi.verify(&psi_input, context, &mut transcript)?;

        // Verify the psi_hat proof
        let psi_hat_input = PiAffgInput::new(
            receiver_auxinfo_public.params().clone(),
            receiver_auxinfo_public.pk().clone(),
            sender_auxinfo_public.pk().clone(),
            receiver_r1_private.K.clone(),
            self.D_hat.clone(),
            self.F_hat.clone(),
            sender_keyshare_public.X,
        );
        let mut transcript = Transcript::new(b"PiAffgProof");
        self.psi_hat
            .verify(&psi_hat_input, context, &mut transcript)?;

        // Verify the psi_prime proof
        let psi_prime_input = CommonInput::new(
            sender_r1_public_broadcast.G.clone(),
            self.Gamma,
            receiver_auxinfo_public.params().scheme().clone(),
            sender_auxinfo_public.pk().clone(),
            g,
        );
        let mut transcript = Transcript::new(b"PiLogProof");
        self.psi_prime
            .verify(&psi_prime_input, context, &mut transcript)?;

        Ok(())
    }

    pub(crate) fn from_message(
        message: &Message,
        context: &impl ProofContext,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_keyshare_public: &KeySharePublic,
        receiver_r1_private: &RoundOnePrivate,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Presign(PresignMessageType::RoundTwo) {
            error!(
                "Encountered unexpected MessageType. Expected {:?}, Got {:?}",
                MessageType::Presign(PresignMessageType::RoundTwo),
                message.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }
        let round_two_public: Self = deserialize!(&message.unverified_bytes)?;

        round_two_public.verify(
            context,
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_keyshare_public,
            receiver_r1_private,
            sender_r1_public_broadcast,
        )?;
        Ok(round_two_public)
    }
}
