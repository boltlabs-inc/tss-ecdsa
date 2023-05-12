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
use zeroize::ZeroizeOnDrop;

#[derive(Clone, ZeroizeOnDrop)]
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

/// Public information produced in round three of the presign protocol.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Public {
    pub delta: Scalar,
    pub Delta: CurvePoint,
    pub psi_double_prime: PiLogProof,
    /// Gamma value included for convenience
    pub Gamma: CurvePoint,
}

impl Public {
    /// Verify the validity of [`Public`] against the sender's [`AuxInfoPublic`]
    /// and [`PublicBroadcast`](crate::presign::round_one::PublicBroadcast)
    /// values.
    ///
    /// Note: The `receiver_...` values must be those of the _caller_ (i.e., the
    /// verifier), and the `sender_...` values must be those of the other party
    /// (i.e., the prover).
    pub(crate) fn verify(
        &self,
        context: &impl ProofContext,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"PiLogProof");
        let psi_double_prime_input = CommonInput::new(
            sender_r1_public_broadcast.K.clone(),
            self.Delta,
            receiver_auxinfo_public.params().scheme().clone(),
            sender_auxinfo_public.pk().clone(),
            self.Gamma,
        );
        self.psi_double_prime
            .verify(&psi_double_prime_input, context, &mut transcript)?;

        Ok(())
    }
}

impl TryFrom<&Message> for Public {
    type Error = InternalError;

    fn try_from(message: &Message) -> std::result::Result<Self, Self::Error> {
        message.check_type(MessageType::Presign(PresignMessageType::RoundThree))?;
        let public: Self = deserialize!(&message.unverified_bytes)?;
        Ok(public)
    }
}

/// Used to bundle the inputs passed to round_three() together
pub(crate) struct RoundThreeInput {
    pub auxinfo_public: AuxInfoPublic,
    pub r2_private: RoundTwoPrivate,
    pub r2_public: RoundTwoPublic,
}
