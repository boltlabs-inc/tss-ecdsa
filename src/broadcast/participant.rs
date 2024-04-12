// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::data::BroadcastData,
    errors::{CallerError, InternalError, Result},
    local_storage::LocalStorage,
    messages::{BroadcastMessageType, Message, MessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    run_only_once_per_tag, Identifier,
};

use crate::participant::Status;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, instrument};

// Local storage data types.
mod storage {
    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Votes;
    impl TypeTag for Votes {
        type Value = HashMap<BroadcastIndex, Vec<u8>>;
    }
}

#[derive(Debug)]
pub(crate) struct BroadcastParticipant {
    /// The current session identifier
    sid: Identifier,
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    /// Status of the protocol execution
    status: Status,
}

#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Debug)]
pub(crate) enum BroadcastTag {
    AuxinfoR1CommitHash,
    KeyGenR1CommitHash,
    KeyRefreshR1CommitHash,
    PresignR1Ciphertexts,
}

#[derive(Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct BroadcastIndex {
    tag: BroadcastTag,
    leader: ParticipantIdentifier,
    other_id: ParticipantIdentifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BroadcastOutput {
    tag: BroadcastTag,
    msg: Message,
}

impl BroadcastOutput {
    pub(crate) fn into_message(self, expected_tag: BroadcastTag) -> Result<Message> {
        if self.tag != expected_tag {
            error!(
                "Incorrect Broadcast Tag on received message. Expected {:?}, got {:?}",
                expected_tag, self.tag
            );
            return Err(InternalError::ProtocolError(None));
        }
        let message = self.msg;
        Ok(message)
    }
}

impl ProtocolParticipant for BroadcastParticipant {
    type Input = ();
    type Output = BroadcastOutput;

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        _input: Self::Input,
    ) -> Result<Self> {
        Ok(Self {
            sid,
            id,
            other_participant_ids,
            local_storage: Default::default(),
            status: Status::Initialized,
        })
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        &self.other_participant_ids
    }

    fn sid(&self) -> Identifier {
        self.sid
    }

    fn ready_type() -> MessageType {
        // I'm not totally confident since broadcast takes a different shape than the
        // other protocols, but this is definitely the first message in the
        // protocol.
        MessageType::Broadcast(BroadcastMessageType::Disperse)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Broadcast
    }

    #[instrument(skip_all, err(Debug))]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "BROADCAST: Player {}: received {:?} from {}",
            self.id(),
            message.message_type(),
            message.from()
        );

        if let Status::ParticipantCompletedBroadcast(participants) = self.status() {
            // The protocol has terminated if the number of participants who
            // have completed a broadcast equals the total number of other
            // participants.
            if participants.len() == self.other_participant_ids.len() {
                Err(CallerError::ProtocolAlreadyTerminated)?;
            }
        }

        match message.message_type() {
            MessageType::Broadcast(BroadcastMessageType::Disperse) => {
                self.handle_round_one_msg(rng, message)
            }
            MessageType::Broadcast(BroadcastMessageType::Redisperse) => {
                self.handle_round_two_msg(rng, message)
            }
            message_type => {
                error!(
                    "Incorrect MessageType given to Broadcast handler. Got: {:?}",
                    message_type
                );
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    fn status(&self) -> &Status {
        &self.status
    }
}

impl InnerProtocolParticipant for BroadcastParticipant {
    type Context = SharedContext;

    /// This method is never used.
    fn retrieve_context(&self) -> <Self as InnerProtocolParticipant>::Context {
        SharedContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.local_storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.local_storage
    }

    fn status_mut(&mut self) -> &mut Status {
        &mut self.status
    }
}

impl BroadcastParticipant {
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message_type: MessageType,
        data: Vec<u8>,
        _sid: Identifier,
        tag: BroadcastTag,
    ) -> Result<Vec<Message>> {
        info!(
            "Generating round one broadcast messages of type: {:?}.",
            message_type
        );

        let b_data = BroadcastData {
            leader: self.id,
            tag,
            message_type,
            data,
        };
        let messages = self.message_for_other_participants(
            MessageType::Broadcast(BroadcastMessageType::Disperse),
            b_data,
        )?;
        Ok(messages)
    }

    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round one broadcast message.");

        // [ [data, votes], [data, votes], ...]
        // for a given tag and sid, only run once
        let data = BroadcastData::from_message(message)?;
        let tag = data.tag.clone();
        // it's possible that all Redisperse messages are received before the original
        // Disperse, causing an output
        let redisperse_outcome = self.process_vote(data, message.id(), message.from())?;
        let disperse_messages =
            run_only_once_per_tag!(self.gen_round_two_msgs(rng, message, message.from()), &tag)?;

        Ok(redisperse_outcome.with_messages(disperse_messages))
    }

    #[instrument(skip_all, err(Debug))]
    fn process_vote(
        &mut self,
        data: BroadcastData,
        sid: Identifier,
        voter: ParticipantIdentifier,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Processing broadcast vote.");

        let other_participant_ids = self.other_participant_ids.clone();
        let message_votes = self.get_from_storage::<storage::Votes>()?;

        // if not already in database, store. else, ignore
        let idx = BroadcastIndex {
            tag: data.tag.clone(),
            leader: data.leader,
            other_id: voter,
        };
        if message_votes.contains_key(&idx) {
            return Ok(ProcessOutcome::Incomplete);
        }
        let _ = message_votes.insert(idx, data.data.clone());

        // check if we've received all the votes for this tag||leader yet
        let mut redispersed_messages: Vec<Vec<u8>> = vec![];
        for oid in other_participant_ids.iter() {
            let idx = BroadcastIndex {
                tag: data.tag.clone(),
                leader: data.leader,
                other_id: *oid,
            };
            match message_votes.get(&idx) {
                Some(value) => redispersed_messages.push(value.clone()),
                None => return Ok(ProcessOutcome::Incomplete),
            };
        }

        // tally the votes
        let mut tally: HashMap<Vec<u8>, usize> = HashMap::new();
        for vote in redispersed_messages.iter() {
            let mut count = tally.remove(vote).unwrap_or(0);
            count += 1;
            let _ = tally.insert(vote.clone(), count);
        }

        // output if every node voted for the same message
        for (k, v) in tally.iter() {
            if *v == self.other_participant_ids.len() {
                let msg = Message::new_from_serialized_data(
                    data.message_type,
                    sid,
                    data.leader,
                    self.id,
                    k.clone(),
                )?;
                let out = BroadcastOutput { tag: data.tag, msg };
                match &mut self.status {
                    Status::Initialized => {
                        self.status = Status::ParticipantCompletedBroadcast(vec![voter]);
                    }
                    Status::ParticipantCompletedBroadcast(participants) => {
                        participants.push(voter);
                    }
                    status => return Err(InternalError::UnexpectedStatus(status.clone())),
                }

                return Ok(ProcessOutcome::Terminated(out));
            }
        }
        error!("Broadcast failed because no message got enough votes");
        Err(InternalError::ProtocolError(None))
    }

    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        leader: ParticipantIdentifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two broadcast messages.");

        let data = BroadcastData::from_message(message)?;
        // todo: handle this more memory-efficiently
        let mut others_minus_leader = self.other_participant_ids.clone();
        others_minus_leader.retain(|&id| id != leader);
        let messages: Vec<Message> = others_minus_leader
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Broadcast(BroadcastMessageType::Redisperse),
                    message.id(),
                    self.id,
                    other_participant_id,
                    &data,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(messages)
    }

    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round two broadcast message.");

        let data = BroadcastData::from_message(message)?;
        if data.leader == self.id() {
            return Ok(ProcessOutcome::Incomplete);
        }
        self.process_vote(data, message.id(), message.from())
    }
}
