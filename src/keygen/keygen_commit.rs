// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{InternalError, Result},
    keygen::keyshare::KeySharePublic,
    messages::{KeygenMessageType, Message, MessageType},
    protocol::{Identifier, ParticipantIdentifier},
    utils::CurvePoint,
    zkp::pisch::PiSchPrecommit,
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{error, instrument};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct KeygenCommit {
    hash: [u8; 32],
}
impl KeygenCommit {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Keygen(KeygenMessageType::R1CommitHash))?;
        let keygen_commit: KeygenCommit = deserialize!(&message.unverified_bytes)?;
        Ok(keygen_commit)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct KeygenDecommit {
    ///`sid` corresponds to a unique session identifier.
    pub sid: Identifier,
    pub sender: ParticipantIdentifier,
    pub rid: [u8; 32],
    pub u_i: [u8; 32],
    pub pk: KeySharePublic,
    pub A: CurvePoint,
}

impl KeygenDecommit {
    ///`sid` corresponds to a unique session identifier.
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        sid: &Identifier,
        sender: &ParticipantIdentifier,
        pk: &KeySharePublic,
        sch_precom: &PiSchPrecommit,
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
            pk: pk.clone(),
            A: *sch_precom.precommitment(),
        }
    }

    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Keygen(KeygenMessageType::R2Decommit))?;
        let keygen_decommit: KeygenDecommit = deserialize!(&message.unverified_bytes)?;
        Ok(keygen_decommit)
    }

    pub(crate) fn get_keyshare(&self) -> &KeySharePublic {
        &self.pk
    }

    pub(crate) fn commit(&self) -> Result<KeygenCommit> {
        let mut transcript = Transcript::new(b"KeyGenR1");
        transcript.append_message(b"decom", &serialize!(&self)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"hashing r1", &mut hash);
        Ok(KeygenCommit { hash })
    }

    #[instrument(skip_all, err(Debug))]
    /// `sid` is a unique session identifier.
    pub(crate) fn verify(
        &self,
        sid: &Identifier,
        sender: &ParticipantIdentifier,
        com: &KeygenCommit,
    ) -> Result<()> {
        let mut transcript = Transcript::new(b"KeyGenR1");
        let mut decom = &mut self.clone();
        decom.sid = *sid;
        decom.sender = *sender;
        transcript.append_message(b"decom", &serialize!(&decom)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"hashing r1", &mut hash);
        let rebuilt_com = KeygenCommit { hash };

        if rebuilt_com == *com {
            Ok(())
        } else {
            error!("decommitment does not match original commitment");
            Err(InternalError::ProtocolError)
        }
    }
}
