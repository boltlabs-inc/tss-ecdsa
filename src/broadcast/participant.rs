// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::data::BroadcastData,
    errors::{InternalError, Result},
    local_storage::LocalStorage,
    messages::{BroadcastMessageType, Message, MessageType},
    participant::{ProcessOutcome, ProtocolParticipant},
    protocol::ParticipantIdentifier,
    run_only_once_per_tag,
    storage::Storage,
    Identifier,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

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
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Old storage mechanism currently used to store persistent data
    ///
    /// TODO #180: To be removed once we remove the need for persistent storage
    main_storage: Storage,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
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
    type Output = BroadcastOutput;

    fn storage(&self) -> &Storage {
        &self.main_storage
    }

    fn storage_mut(&mut self) -> &mut Storage {
        &mut self.main_storage
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &Vec<ParticipantIdentifier> {
        &self.other_participant_ids
    }

    #[instrument(skip_all, err(Debug))]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        _main_storage: &mut Storage,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing broadcast message.");

        match message.message_type() {
            MessageType::Broadcast(BroadcastMessageType::Disperse) => {
                let (output_option, messages) = self.handle_round_one_msg(rng, message)?;
                Ok(ProcessOutcome::from(output_option, messages))
            }
            MessageType::Broadcast(BroadcastMessageType::Redisperse) => {
                let (output_option, messages) = self.handle_round_two_msg(rng, message)?;
                Ok(ProcessOutcome::from(output_option, messages))
            }
            _ => Err(InternalError::MisroutedMessage),
        }
    }
}

impl BroadcastParticipant {
    pub(crate) fn from_ids(
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
    ) -> Self {
        Self {
            id,
            other_participant_ids,
            main_storage: Storage::new(),
            local_storage: Default::default(),
        }
    }

    #[instrument(skip_all, err(Debug))]
    pub(crate) fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message_type: &MessageType,
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
            message_type: *message_type,
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
    ) -> Result<(Option<BroadcastOutput>, Vec<Message>)> {
        info!("Handling round one broadcast message.");

        // [ [data, votes], [data, votes], ...]
        // for a given tag and sid, only run once
        let data = BroadcastData::from_message(message)?;
        let tag = data.tag.clone();
        // it's possible that all Redisperse messages are received before the original
        // Disperse, causing an output
        let output_option = self.process_vote(data, message.id(), message.from())?;
        let messages = run_only_once_per_tag!(
            self.gen_round_two_msgs(rng, message, message.from()),
            message.id(),
            &tag
        )?;
        Ok((output_option, messages))
    }

    #[instrument(skip_all, err(Debug))]
    fn process_vote(
        &mut self,
        data: BroadcastData,
        sid: Identifier,
        voter: ParticipantIdentifier,
    ) -> Result<Option<BroadcastOutput>> {
        info!("Processing broadcast vote.");

        let message_votes = match self
            .local_storage
            .retrieve_mut::<storage::Votes>(sid, self.id())
        {
            Ok(votes) => votes,
            Err(_) => {
                // If we can't find an entry we assume that means it doesn't
                // exist, so we create the entry and immediately retrieve it.
                self.local_storage
                    .store::<storage::Votes>(sid, self.id(), Default::default());
                self.local_storage
                    .retrieve_mut::<storage::Votes>(sid, self.id())?
            }
        };

        // if not already in database, store. else, ignore
        let idx = BroadcastIndex {
            tag: data.tag.clone(),
            leader: data.leader,
            other_id: voter,
        };
        if message_votes.contains_key(&idx) {
            return Ok(None);
        }
        let _ = message_votes.insert(idx, data.data.clone());

        // check if we've received all the votes for this tag||leader yet
        let mut redispersed_messages: Vec<Vec<u8>> = vec![];
        for oid in self.other_participant_ids.iter() {
            let idx = BroadcastIndex {
                tag: data.tag.clone(),
                leader: data.leader,
                other_id: *oid,
            };
            match message_votes.get(&idx) {
                Some(value) => redispersed_messages.push(value.clone()),
                None => return Ok(None),
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
                let msg = Message::new(data.message_type, sid, data.leader, self.id(), k);
                let out = BroadcastOutput { tag: data.tag, msg };
                return Ok(Some(out));
            }
        }
        Err(InternalError::BroadcastFailure(
            "No message got enough votes".to_string(),
        ))
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
    ) -> Result<(Option<BroadcastOutput>, Vec<Message>)> {
        info!("Handling round two broadcast message.");

        let data = BroadcastData::from_message(message)?;
        if data.leader == self.id() {
            return Ok((None, vec![]));
        }
        let output_option = self.process_vote(data, message.id(), message.from())?;
        Ok((output_option, vec![]))
    }
}
