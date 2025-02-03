// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::AuxInfoPublic,
    curve::{CurveTrait, ScalarTrait},
    errors::{InternalError, Result},
    messages::{Message, MessageType, PresignMessageType},
    presign::{
        participant::ParticipantPresignContext,
        round_one::PublicBroadcast as RoundOnePublicBroadcast,
        round_two::{Private as RoundTwoPrivate, Public as RoundTwoPublic},
    },
    zkp::{
        pilog::{CommonInput, PiLogProof},
        Proof,
    },
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use zeroize::ZeroizeOnDrop;

#[derive(Clone, ZeroizeOnDrop)]
pub(crate) struct Private<C: CurveTrait> {
    pub k: BigNumber,
    pub chi: C::Scalar,
    #[zeroize(skip)]
    pub Gamma: C,
    #[zeroize(skip)]
    pub delta: C::Scalar,
    #[zeroize(skip)]
    pub Delta: C,
}

impl<C: CurveTrait + Debug> Debug for Private<C> {
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
pub(crate) struct Public<C: CurveTrait> {
    pub delta: C::Scalar,
    #[serde(bound(deserialize = "C: CurveTrait"))]
    pub Delta: C,
    #[serde(bound(deserialize = "C: CurveTrait"))]
    pub psi_double_prime: PiLogProof<C>,
    /// Gamma value included for convenience
    #[serde(bound(deserialize = "C: CurveTrait"))]
    pub Gamma: C,
}

impl<C: CurveTrait> Public<C> {
    /// Verify the validity of [`Public`] against the prover's [`AuxInfoPublic`]
    /// and [`PublicBroadcast`](crate::presign::round_one::PublicBroadcast)
    /// values.
    pub(crate) fn verify(
        self,
        context: &ParticipantPresignContext<C>,
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

impl<C: CurveTrait> TryFrom<&Message> for Public<C> {
    type Error = InternalError;

    fn try_from(message: &Message) -> std::result::Result<Self, Self::Error> {
        message.check_type(MessageType::Presign(PresignMessageType::RoundThree))?;
        let public: Self = deserialize!(&message.unverified_bytes)?;

        // Normal `Scalar` deserialization doesn't check that the value is in range.
        // Here we convert to bytes and back, using the checked `from_repr` method to
        // make sure the value is a valid, canonical Scalar.
        if C::Scalar::from_bytes(public.delta.to_bytes().as_slice())?.is_none() {
            error!("Deserialized round 3 message `delta` field is out of range");
            Err(InternalError::ProtocolError(Some(message.from())))?
        }
        Ok(public)
    }
}

/// Used to bundle the inputs passed to round_three() together
pub(crate) struct Input<C> {
    pub auxinfo_public: AuxInfoPublic,
    pub r2_private: RoundTwoPrivate,
    pub r2_public: RoundTwoPublic<C>,
}
