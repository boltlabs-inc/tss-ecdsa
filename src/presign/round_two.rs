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
    keygen::keyshare::KeySharePublic,
    messages::{Message, MessageType, PresignMessageType},
    paillier::PaillierCiphertext,
    presign::round_one::{Private as RoundOnePrivate, PublicBroadcast as RoundOnePublicBroadcast},
    utils::k256_order,
    zkp::{
        piaffg::{PiAffgInput, PiAffgProof},
        pilog::{PiLogInput, PiLogProof},
        Proof,
    },
    CurvePoint,
};
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Private {
    pub beta: BigNumber,
    pub beta_hat: BigNumber,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Public {
    pub D: PaillierCiphertext,
    pub D_hat: PaillierCiphertext,
    pub F: PaillierCiphertext,
    pub F_hat: PaillierCiphertext,
    pub Gamma: CurvePoint,
    pub psi: PiAffgProof,
    pub psi_hat: PiAffgProof,
    pub psi_prime: PiLogProof,
}

impl Public {
    fn verify(
        &self,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_keyshare_public: &KeySharePublic,
        receiver_r1_private: &RoundOnePrivate,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<()> {
        let g = CurvePoint::GENERATOR;

        // Verify the psi proof
        let psi_input = PiAffgInput::new(
            &receiver_auxinfo_public.params,
            &g,
            receiver_auxinfo_public.pk.n(),
            sender_auxinfo_public.pk.n(),
            &receiver_r1_private.K,
            &self.D,
            &self.F,
            &self.Gamma,
        );
        self.psi.verify(&psi_input)?;

        // Verify the psi_hat proof
        let psi_hat_input = PiAffgInput::new(
            &receiver_auxinfo_public.params,
            &g,
            receiver_auxinfo_public.pk.n(),
            sender_auxinfo_public.pk.n(),
            &receiver_r1_private.K,
            &self.D_hat,
            &self.F_hat,
            &sender_keyshare_public.X,
        );
        self.psi_hat.verify(&psi_hat_input)?;

        // Verify the psi_prime proof
        let psi_prime_input = PiLogInput::new(
            &receiver_auxinfo_public.params,
            &k256_order(),
            sender_auxinfo_public.pk.n(),
            &sender_r1_public_broadcast.G,
            &self.Gamma,
            &g,
        );
        self.psi_prime.verify(&psi_prime_input)?;

        Ok(())
    }

    pub(crate) fn from_message(
        message: &Message,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_keyshare_public: &KeySharePublic,
        receiver_r1_private: &RoundOnePrivate,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Presign(PresignMessageType::RoundTwo) {
            return bail!("Wrong message type, expected MessageType::RoundTwo");
        }
        let round_two_public: Self = deserialize!(&message.unverified_bytes)?;

        match round_two_public.verify(
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_keyshare_public,
            receiver_r1_private,
            sender_r1_public_broadcast,
        ) {
            Ok(()) => Ok(round_two_public),
            Err(e) => bail!("Failed to verify round two public: {}", e),
        }
    }
}
