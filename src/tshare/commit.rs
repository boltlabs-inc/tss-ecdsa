// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use super::share::CoeffPublic;
use crate::{
    errors::{InternalError, Result},
    messages::{Message, MessageType, TshareMessageType},
    protocol::{Identifier, ParticipantIdentifier},
    utils::CurvePoint,
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::error;

/// Public commitment to `TshareDecommit` in round 1.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct TshareCommit {
    hash: [u8; 32],
}
impl TshareCommit {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Tshare(TshareMessageType::R1CommitHash))?;
        let tshare_commit: TshareCommit = deserialize!(&message.unverified_bytes)?;
        Ok(tshare_commit)
    }
}

/// Decommitment published in round 2.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct TshareDecommit {
    sid: Identifier,
    sender: ParticipantIdentifier,
    u_i: [u8; 32], // The blinding factor is never read but it is included in the commitment.
    pub rid: [u8; 32],
    pub coeff_publics: Vec<CoeffPublic>,
    pub precom: CurvePoint,
}

impl TshareDecommit {
    ///`sid` corresponds to a unique session identifier.
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        sid: &Identifier,
        sender: &ParticipantIdentifier,
        coeff_publics: &[CoeffPublic],
        sch_precom: CurvePoint,
    ) -> Self {
        let mut rid = [0u8; 32];
        let mut u_i = [0u8; 32];
        rng.fill_bytes(rid.as_mut_slice());
        rng.fill_bytes(u_i.as_mut_slice());
        Self {
            sid: *sid,
            sender: *sender,
            rid,
            u_i,
            coeff_publics: coeff_publics.to_vec(),
            precom: sch_precom,
        }
    }

    /// Deserialize a TshareDecommit from a message and verify it.
    pub(crate) fn from_message(message: &Message, com: &TshareCommit) -> Result<Self> {
        message.check_type(MessageType::Tshare(TshareMessageType::R2Decommit))?;
        let tshare_decommit: TshareDecommit = deserialize!(&message.unverified_bytes)?;
        tshare_decommit.verify(message.id(), message.from(), com)?;
        Ok(tshare_decommit)
    }

    pub(crate) fn commit(&self) -> Result<TshareCommit> {
        let mut transcript = Transcript::new(b"TshareR1");
        transcript.append_message(b"decom", &serialize!(&self)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"hashing r1", &mut hash);
        Ok(TshareCommit { hash })
    }

    /// Verify this TshareDecommit against a commitment and expected
    /// content.
    fn verify(
        &self,
        sid: Identifier,
        sender: ParticipantIdentifier,
        com: &TshareCommit,
    ) -> Result<()> {
        // Check the commitment.
        let rebuilt_com = self.commit()?;
        if &rebuilt_com != com {
            error!("decommitment does not match original commitment");
            return Err(InternalError::ProtocolError(Some(sender)));
        }

        // Check the session ID and sender ID.
        if self.sid != sid {
            error!("Incorrect session ID");
            return Err(InternalError::ProtocolError(Some(sender)));
        }
        if self.sender != sender {
            error!("Incorrect sender ID");
            return Err(InternalError::ProtocolError(Some(sender)));
        }

        Ok(())
    }
}

// Implement custom Debug to avoid leaking secret information.
impl std::fmt::Debug for TshareDecommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TshareDecommit")
            .field("sid", &self.sid)
            .field("sender", &self.sender)
            .field("coeff_publics", &self.coeff_publics)
            .field("...", &"[redacted]")
            .finish()
    }
}
