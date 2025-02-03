// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::{info::AuxInfoPublic, participant::AuxInfoParticipant},
    curve::CurveTrait,
    errors::{InternalError, Result},
    messages::{AuxinfoMessageType, Message, MessageType},
    parameters::PRIME_BITS,
    participant::{InnerProtocolParticipant, ProtocolParticipant},
    protocol::{Identifier, ParticipantIdentifier},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, marker::PhantomData};
use tracing::{error, instrument};

/// The commitment produced by [`CommitmentScheme`].
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct Commitment {
    hash: [u8; 32],
}

impl Commitment {
    /// Extract the [`Commitment`] from the given [`Message`].
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash))?;
        let com: Commitment = deserialize!(&message.unverified_bytes)?;
        Ok(com)
    }
}

/// Hash-based commitment scheme for the auxinfo protocol.
///
/// Note that the decommitment is exactly the commitment scheme itself. That is,
/// to send decommit to a validly produced [`Commitment`] one needs to send
/// [`CommitmentScheme`] itself.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CommitmentScheme<C: CurveTrait> {
    /// A unique session identifier (`ssid` in the paper).
    sid: Identifier,
    /// This participant's [`ParticipantIdentifier`] (`i` in the paper).
    pid: ParticipantIdentifier,
    /// This participant's [`AuxInfoPublic`] (`N_i, s_i, t_i, ψhat_i` in the
    /// paper).
    public_key: AuxInfoPublic,
    /// This participant's randomness (`ρ_i` in the paper).
    ///
    /// This randomness is combined with all other participants' randomness and
    /// used as input to proofs in later rounds of the `auxinfo` protocol.
    randomness: [u8; 32],
    /// This participant's commitment randomness (`u_i` in the paper).
    ///
    /// This randomness is to ensure that the hash-based commitment is properly
    /// randomized.
    commit_randomness: [u8; 32],
    /// Phantom data to ensure that the commitment scheme is curve-agnostic.
    _phantom: PhantomData<C>,
}

impl<C: CurveTrait> Debug for CommitmentScheme<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacting randomness and commit_randomness because I'm not sure how
        // sensitive they are. If later analysis suggests they're fine to print,
        // please udpate accordingly.
        f.debug_struct("CommitmentScheme")
            .field("sid", &self.sid)
            .field("pid", &self.pid)
            .field("randomness", &"[redacted]")
            .field("commit_randomness", &"[redacted]")
            .field("public_key", &"[redacted -- tooooo long]") //self.public_keys)
            .finish()
    }
}

impl<C: CurveTrait> CommitmentScheme<C> {
    /// Construct a new [`CommitmentScheme`] using the provided unique session
    /// [`Identifier`], [`AuxInfoParticipant`], and [`AuxInfoPublic`].
    ///
    /// This method verifies that the [`AuxInfoPublic`] provided successfully
    /// verifies according to the context associated with
    /// [`AuxInfoParticipant`].
    pub(crate) fn new<R: RngCore + CryptoRng>(
        sid: Identifier,
        auxinfo_participant: &AuxInfoParticipant<C>,
        public_key: AuxInfoPublic,
        rng: &mut R,
    ) -> Result<Self> {
        let mut rid = [0u8; 32];
        let mut u_i = [0u8; 32];
        rng.fill_bytes(rid.as_mut_slice());
        rng.fill_bytes(u_i.as_mut_slice());

        public_key
            .clone()
            .verify(&auxinfo_participant.retrieve_context())?;
        if auxinfo_participant.id() != public_key.participant() {
            error!("Created auxinfo commitment scheme with different participant IDs in the sender and public_key fields");
            return Err(InternalError::InternalInvariantFailed);
        }

        Ok(Self {
            sid,
            pid: auxinfo_participant.id(),
            randomness: rid,
            commit_randomness: u_i,
            public_key,
            _phantom: PhantomData,
        })
    }

    /// Converts a [`Message`] type into an [`CommitmentScheme`] type.
    ///
    /// This method verifies all the internal [`CommitmentScheme`] values.
    pub(crate) fn from_message(
        message: &Message,
        context: &<AuxInfoParticipant<C> as InnerProtocolParticipant>::Context,
    ) -> Result<Self> {
        message.check_type(MessageType::Auxinfo(AuxinfoMessageType::R2Decommit))?;
        let scheme: CommitmentScheme<C> = deserialize!(&message.unverified_bytes)?;

        // Public parameters in this decommit must be consistent with each other...
        scheme.clone().public_key.verify(context)?;

        // ...and the (shared) modulus must be of the expected length
        if scheme.modulus().bit_length() != 2 * PRIME_BITS {
            error!(
                "Expected a commitment scheme with a modulus of {} bits, but got {} bits",
                2 * PRIME_BITS,
                scheme.modulus().bit_length()
            )
        }

        // Owner must be consistent across message, public keys, and decommit
        if scheme.public_key.participant() != scheme.pid {
            error!(
                "Deserialized AuxInfoDecommit has different participant IDs in the sender ({}) and public_keys ({}) fields",
                scheme.pid,
                scheme.public_key.participant(),
            );
            return Err(InternalError::ProtocolError(Some(message.from())));
        }
        if scheme.pid != message.from() {
            error!(
                "Deserialized AuxInfoDecommit claiming to be from a different sender ({}) than the message was from ({})",
                scheme.pid,
                message.from()
            );
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        // Session ID must be correct
        if scheme.sid != message.id() {
            error!(
                "Deserialized AuxInfoDecommit has different session ID ({}) than the message it came with ({})",
                scheme.sid,
                message.id()
            );
            return Err(InternalError::ProtocolError(Some(scheme.pid)));
        }

        Ok(scheme)
    }

    pub(crate) fn rid(&self) -> [u8; 32] {
        self.randomness
    }

    pub(crate) fn into_public(self) -> AuxInfoPublic {
        self.public_key
    }

    fn modulus(&self) -> &BigNumber {
        // Note: by construction, this should be the same as the modulus in
        // `self.public_key.scheme()`.
        self.public_key.pk().modulus()
    }

    pub(crate) fn commit(&self) -> Result<Commitment> {
        let mut transcript = Transcript::new(b"AuxInfo Round 1");
        transcript.append_message(b"Commitment scheme", &serialize!(&self)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"Hash of round 1", &mut hash);
        Ok(Commitment { hash })
    }

    /// Verify that this type corresponds to the given [`CommitmentScheme`].
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn verify(
        &self,
        sid: &Identifier,
        sender: &ParticipantIdentifier,
        com: &Commitment,
    ) -> Result<()> {
        if *sid != self.sid {
            error!(
                "Decommitment has the wrong session ID. Got {}, expected {}.",
                self.sid, sid
            );
            return Err(InternalError::ProtocolError(Some(*sender)));
        }
        if *sender != self.pid {
            error!(
                "Decommitment has the wrong sender ID. Got {}, expected {}.",
                self.pid, sender
            );
            return Err(InternalError::ProtocolError(Some(*sender)));
        }

        let rebuilt_com = self.commit()?;

        if rebuilt_com != *com {
            error!("Commitment verification failed; does not match commitment. Commitment scheme: {:?}. Commitment: {:?}", self, com);
            return Err(InternalError::ProtocolError(Some(*sender)));
        }

        Ok(())
    }
}
