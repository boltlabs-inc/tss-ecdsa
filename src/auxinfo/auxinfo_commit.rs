// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::info::AuxInfoPublic,
    errors::Result,
    messages::{AuxinfoMessageType, Message, MessageType},
    protocol::{Identifier, ParticipantIdentifier},
};
use merlin::Transcript;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct AuxInfoCommit {
    hash: [u8; 32],
}
impl AuxInfoCommit {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash) {
            return bail!("Wrong message type, expected MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash)");
        }
        let auxinfo_commit: AuxInfoCommit = deserialize!(&message.unverified_bytes)?;
        Ok(auxinfo_commit)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoDecommit {
    pub sid: Identifier,
    pub sender: ParticipantIdentifier,
    pub rid: [u8; 32],
    pub u_i: [u8; 32],
    pub pk: AuxInfoPublic,
}

impl AuxInfoDecommit {
    pub(crate) fn new(
        sid: &Identifier,
        sender: &ParticipantIdentifier,
        pk: &AuxInfoPublic,
    ) -> Self {
        let mut rng = rand::rngs::OsRng;
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
        }
    }

    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Auxinfo(AuxinfoMessageType::R2Decommit) {
            return bail!(
                "Wrong message type, expected MessageType::Auxinfo(AuxinfoMessageType::R2Decommit)"
            );
        }
        let auxinfo_decommit: AuxInfoDecommit = deserialize!(&message.unverified_bytes)?;
        Ok(auxinfo_decommit)
    }

    pub(crate) fn get_pk(&self) -> &AuxInfoPublic {
        &self.pk
    }

    pub(crate) fn commit(&self) -> Result<AuxInfoCommit> {
        let mut transcript = Transcript::new(b"AuxinfoR1");
        transcript.append_message(b"decom", &serialize!(&self)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"hashing r1", &mut hash);
        Ok(AuxInfoCommit { hash })
    }

    pub(crate) fn verify(
        &self,
        sid: &Identifier,
        sender: &ParticipantIdentifier,
        com: &AuxInfoCommit,
    ) -> Result<bool> {
        let mut transcript = Transcript::new(b"AuxinfoR1");
        let mut decom = &mut self.clone();
        decom.sid = *sid;
        decom.sender = *sender;
        transcript.append_message(b"decom", &serialize!(&decom)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"hashing r1", &mut hash);
        let rebuilt_com = AuxInfoCommit { hash };
        Ok(rebuilt_com == *com)
    }
}
