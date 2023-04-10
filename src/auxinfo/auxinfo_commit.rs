// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::{info::AuxInfoPublic, participant::AuxInfoParticipant},
    errors::{InternalError, Result},
    messages::{AuxinfoMessageType, Message, MessageType},
    participant::{InnerProtocolParticipant, ProtocolParticipant},
    protocol::{Identifier, ParticipantIdentifier},
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::{error, instrument};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct AuxInfoCommit {
    hash: [u8; 32],
}
impl AuxInfoCommit {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash) {
            error!(
                "Encountered unexpected MessageType. Expected {:?}, Got {:?}",
                MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash),
                message.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }
        let auxinfo_commit: AuxInfoCommit = deserialize!(&message.unverified_bytes)?;
        Ok(auxinfo_commit)
    }
}

#[derive(Serialize, Deserialize, Clone)]
///`sid` corresponds to a unique session identifier.
pub(crate) struct AuxInfoDecommit {
    sid: Identifier,
    sender: ParticipantIdentifier,
    rid: [u8; 32],
    u_i: [u8; 32],
    public_keys: AuxInfoPublic,
}

impl Debug for AuxInfoDecommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacting rid and u_i because I'm not sure how sensitive they are. If later
        // analysis suggests they're fine to print, please udpate accordingly.
        f.debug_struct("AuxInfoDecommit")
            .field("sid", &self.sid)
            .field("sender", &self.sender)
            .field("rid", &"[redacted]")
            .field("u_i", &"[redacted]")
            .field("public keys", &"[redacted -- tooooo long]") //self.public_keys)
            .finish()
    }
}

impl AuxInfoDecommit {
    ///`sid` corresponds to a unique session identifier.
    pub(crate) fn new<R: RngCore + CryptoRng>(
        auxinfo_participant: &AuxInfoParticipant,
        rng: &mut R,
        sid: &Identifier,
        public_keys: AuxInfoPublic,
    ) -> Result<Self> {
        let mut rid = [0u8; 32];
        let mut u_i = [0u8; 32];
        rng.fill_bytes(rid.as_mut_slice());
        rng.fill_bytes(u_i.as_mut_slice());

        public_keys.verify(&auxinfo_participant.retrieve_context())?;
        if &auxinfo_participant.id() != public_keys.participant() {
            error!("Created AuxInfoDecommit with different participant IDs in the sender and public_keys fields");
            return Err(InternalError::InternalInvariantFailed);
        }

        Ok(Self {
            sid: *sid,
            sender: auxinfo_participant.id(),
            rid,
            u_i,
            public_keys,
        })
    }

    pub(crate) fn from_message(
        message: &Message,
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Auxinfo(AuxinfoMessageType::R2Decommit) {
            error!(
                "Encountered unexpected MessageType. Expected {:?}, Got {:?}",
                MessageType::Auxinfo(AuxinfoMessageType::R2Decommit),
                message.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }
        let auxinfo_decommit: AuxInfoDecommit = deserialize!(&message.unverified_bytes)?;

        // Public parameters in this decommit must be consistent with each other
        auxinfo_decommit.public_keys.verify(context)?;

        // Owner must be consistent across message, public keys, and decommit
        if *auxinfo_decommit.public_keys.participant() != auxinfo_decommit.sender {
            error!(
                "Deserialized AuxInfoDecommit has different participant IDs in the sender ({}) and public_keys ({}) fields",
                auxinfo_decommit.sender,
                auxinfo_decommit.public_keys.participant(),
            );
            return Err(InternalError::ProtocolError);
        }
        if auxinfo_decommit.sender != message.from() {
            error!(
                "Deserialized AuxInfoDecommit claiming to be from a different sender ({}) than the message was from ({})",
                auxinfo_decommit.sender,
                message.from()
            );
            return Err(InternalError::ProtocolError);
        }

        // Session ID must be correct
        if auxinfo_decommit.sid != message.id() {
            error!(
                "Deserialized AuxInfoDecommit has different session ID ({}) than the message it came with ({})",
                auxinfo_decommit.sid,
                message.id()
            );
            return Err(InternalError::ProtocolError);
        }

        Ok(auxinfo_decommit)
    }

    pub(crate) fn rid(&self) -> [u8; 32] {
        self.rid
    }

    pub(crate) fn into_public(self) -> AuxInfoPublic {
        self.public_keys
    }

    pub(crate) fn commit(&self) -> Result<AuxInfoCommit> {
        let mut transcript = Transcript::new(b"AuxinfoR1");
        transcript.append_message(b"decom", &serialize!(&self)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"hashing r1", &mut hash);
        Ok(AuxInfoCommit { hash })
    }

    /// Verify that this [`AuxInfoDecommit`] corresponds to the given
    /// [`AuxInfoCommit`].
    /// `sid` is a unique session identifier.
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn verify(
        &self,
        sid: &Identifier,
        sender: &ParticipantIdentifier,
        com: &AuxInfoCommit,
    ) -> Result<()> {
        if *sid != self.sid {
            error!(
                "Decommitment has the wrong session ID. Got {}, expected {}.",
                self.sid, sid
            );
            return Err(InternalError::ProtocolError);
        }
        if *sender != self.sender {
            error!(
                "Decommitment has the wrong sender ID. Got {}, expected {}.",
                self.sender, sender
            );
            return Err(InternalError::ProtocolError);
        }

        let rebuilt_com = self.commit()?;

        if rebuilt_com != *com {
            error!("Commitment verification failed; does not match commitment. Decommitment: {:?}. Commitment: {:?}", self, com);
            return Err(InternalError::ProtocolError);
        }

        Ok(())
    }
}
