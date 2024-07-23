// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::AuxInfoPublic,
    errors::{InternalError, Result},
    messages::{Message, MessageType, PresignMessageType},
    presign::{
        participant::ParticipantPresignContext,
        round_one::PublicBroadcast as RoundOnePublicBroadcast,
        round_two::{Private as RoundTwoPrivate, Public as RoundTwoPublic},
    },
    curve_point::CurvePoint,
    zkp::{
        pilog::{CommonInput, PiLogProof},
        Proof,
    },
};
use k256::{elliptic_curve::PrimeField, Scalar};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
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
///
/// This type implements [`TryFrom`] on [`Message`], which validates that
/// [`Message`] is a valid serialization of `Public`, but _not_ that `Public` is
/// necessarily valid (i.e., that all the components are valid with respect to
/// each other); use [`Public::verify`] to check this latter condition.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Public {
    pub delta: Scalar,
    pub Delta: CurvePoint,
    pub psi_double_prime: PiLogProof<CurvePoint>,
    /// Gamma value included for convenience
    pub Gamma: CurvePoint,
}

impl Public {
    /// Verify the validity of [`Public`] against the prover's [`AuxInfoPublic`]
    /// and [`PublicBroadcast`](crate::presign::round_one::PublicBroadcast)
    /// values.
    pub(crate) fn verify(
        self,
        context: &ParticipantPresignContext,
        verifier_auxinfo_public: &AuxInfoPublic,
        prover_auxinfo_public: &AuxInfoPublic,
        prover_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"PiLogProof");
        let psi_double_prime_input = CommonInput::new(
            &prover_r1_public_broadcast.K,
            &self.Delta,
            verifier_auxinfo_public.params().scheme(),
            prover_auxinfo_public.pk(),
            &self.Gamma,
        );
        self.psi_double_prime
            .verify(psi_double_prime_input, context, &mut transcript)?;

        Ok(())
    }
}

impl TryFrom<&Message> for Public {
    type Error = InternalError;

    fn try_from(message: &Message) -> std::result::Result<Self, Self::Error> {
        message.check_type(MessageType::Presign(PresignMessageType::RoundThree))?;
        let public: Self = deserialize!(&message.unverified_bytes)?;

        // Normal `Scalar` deserialization doesn't check that the value is in range.
        // Here we convert to bytes and back, using the checked `from_repr` method to
        // make sure the value is a valid, canonical Scalar.
        if Scalar::from_repr(public.delta.to_bytes()).is_none().into() {
            error!("Deserialized round 3 message `delta` field is out of range");
            Err(InternalError::ProtocolError(Some(message.from())))?
        }
        Ok(public)
    }
}

/// Used to bundle the inputs passed to round_three() together
pub(crate) struct Input {
    pub auxinfo_public: AuxInfoPublic,
    pub r2_private: RoundTwoPrivate,
    pub r2_public: RoundTwoPublic,
}
