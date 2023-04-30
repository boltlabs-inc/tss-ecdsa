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

/// Protocol status for [`BroadcastParticipant`].
#[derive(Debug, PartialEq)]
pub enum Status {
    /// The protocol has been initialized, but no participants have completed a
    /// broadcast.
    Initialized,
    /// A vector of participants that have completed a broadcast.
    ///
    /// This vector does _not_ correspond to those participants that have
    /// _initialized_ (and hence successfully completed) a broadcast, but rather
    /// the participants who, when either sending a message or _forwarding_ a
    /// message, resulted in the completion of the broadcast. Since all
    /// participants broadcast messages at the same time, this is used to track
    /// termination of the protocol by tracking the vector _size_: If the size
    /// is equal to the number of other participants then the broadcast has
    /// completed (as this equates to this participant receiving the broadcasts
    /// of all other participants, regardless of which participant was the one
    /// who sent the final message "completing" a given broadcast).
    ParticipantCompletedBroadcast(Vec<ParticipantIdentifier>),
}

#[derive(Debug)]
pub(crate) struct BroadcastParticipant {
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
    pub(crate) tag: BroadcastTag,
    pub(crate) msg: Message,
}

impl ProtocolParticipant for BroadcastParticipant {
    type Input = ();
    type Output = BroadcastOutput;
    type Status = Status;

    fn new(id: ParticipantIdentifier, other_participant_ids: Vec<ParticipantIdentifier>) -> Self {
        Self {
            id,
            other_participant_ids,
            local_storage: Default::default(),
            status: Status::Initialized,
        }
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &Vec<ParticipantIdentifier> {
        &self.other_participant_ids
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
        _: &Self::Input,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing broadcast message.");

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

    fn status(&self) -> &Self::Status {
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
}

impl BroadcastParticipant {
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message_type: MessageType,
        data: Vec<u8>,
        sid: Identifier,
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
        let b_data_bytes = serialize!(&b_data)?;
        let messages: Vec<Message> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Broadcast(BroadcastMessageType::Disperse),
                    sid,
                    self.id,
                    other_participant_id,
                    &b_data_bytes,
                )
            })
            .collect();
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
                let msg = Message::new(data.message_type, sid, data.leader, self.id, k);
                let out = BroadcastOutput { tag: data.tag, msg };
                match &mut self.status {
                    Status::Initialized => {
                        self.status = Status::ParticipantCompletedBroadcast(vec![voter]);
                    }
                    Status::ParticipantCompletedBroadcast(participants) => {
                        participants.push(voter);
                    }
                }

                return Ok(ProcessOutcome::Terminated(out));
            }
        }
        error!("Broadcast failed because no message got enough votes");
        Err(InternalError::ProtocolError)
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
        let data_bytes = serialize!(&data)?;
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
                    &data_bytes,
                )
            })
            .collect();
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
