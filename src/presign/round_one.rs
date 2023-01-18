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
    paillier::{PaillierCiphertext, PaillierNonce},
    zkp::{pienc::PiEncProof, setup::ZkSetupParameters, Proof},
};
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Private {
    pub k: BigNumber,
    pub rho: PaillierNonce,
    pub gamma: BigNumber,
    pub nu: PaillierNonce,
    pub G: PaillierCiphertext, // Technically can be public but is only one per party
    pub K: PaillierCiphertext, // Technically can be public but is only one per party
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Public {
    pub proof: PiEncProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PublicBroadcast {
    pub K: PaillierCiphertext,
    pub G: PaillierCiphertext,
}

impl Public {
    /// Verify M(vrfy, Π^enc_i, (ssid, j), (I_ε, K_j), ψ_{i,j}) = 1
    /// setup_params should be the receiving party's setup parameters
    /// the modulus N should be the sending party's modulus N
    fn verify(
        &self,
        receiver_setup_params: &ZkSetupParameters,
        sender_modulus: &BigNumber,
        broadcasted_params: &PublicBroadcast,
    ) -> Result<()> {
        let input = crate::zkp::pienc::PiEncInput::new(
            receiver_setup_params,
            sender_modulus,
            &broadcasted_params.K,
        );

        self.proof.verify(&input)
    }

    pub(crate) fn from_message(
        message: &Message,
        receiver_keygen_public: &AuxInfoPublic,
        sender_keygen_public: &AuxInfoPublic,
        broadcasted_params: &PublicBroadcast,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Presign(PresignMessageType::RoundOne) {
            return bail!("Wrong message type, expected MessageType::RoundOne");
        }
        let round_one_public: Self = deserialize!(&message.unverified_bytes)?;

        match round_one_public.verify(
            &receiver_keygen_public.params,
            sender_keygen_public.pk.n(),
            broadcasted_params,
        ) {
            Ok(()) => Ok(round_one_public),
            Err(e) => bail!("Failed to verify round one public: {}", e),
        }
    }
}
