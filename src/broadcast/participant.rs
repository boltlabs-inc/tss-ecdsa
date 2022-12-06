// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::data::BroadcastData,
    errors::Result,
    messages::{BroadcastMessageType, Message, MessageType},
    participant::ProtocolParticipant,
    protocol::ParticipantIdentifier,
    run_only_once_per_tag,
    storage::{StorableType, Storage},
    Identifier,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct BroadcastParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    storage: Storage,
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

#[derive(Serialize, Deserialize)]
pub(crate) struct BroadcastOutput {
    pub(crate) tag: BroadcastTag,
    pub(crate) msg: Message,
}

impl ProtocolParticipant for BroadcastParticipant {
    fn storage(&self) -> &Storage {
        &self.storage
    }

    fn storage_mut(&mut self) -> &mut Storage {
        &mut self.storage
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
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
            storage: Storage::new(),
        }
    }

    pub(crate) fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<(Option<BroadcastOutput>, Vec<Message>)> {
        match message.message_type() {
            MessageType::Broadcast(BroadcastMessageType::Disperse) => {
                let (output_option, messages) = self.handle_round_one_msg(rng, message)?;
                Ok((output_option, messages))
            }
            MessageType::Broadcast(BroadcastMessageType::Redisperse) => {
                let (output_option, messages) = self.handle_round_two_msg(rng, message)?;
                Ok((output_option, messages))
            }
            _ => {
                bail!("Attempting to process a non-broadcast message with a broadcast participant")
            }
        }
    }

    pub(crate) fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message_type: &MessageType,
        data: Vec<u8>,
        sid: Identifier,
        tag: BroadcastTag,
    ) -> Result<Vec<Message>> {
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

    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<(Option<BroadcastOutput>, Vec<Message>)> {
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

    fn process_vote(
        &mut self,
        data: BroadcastData,
        sid: Identifier,
        voter: ParticipantIdentifier,
    ) -> Result<Option<BroadcastOutput>> {
        let mut message_votes: HashMap<BroadcastIndex, Vec<u8>> =
            match self
                .storage
                .retrieve(StorableType::BroadcastSet, sid, self.id())
            {
                Ok(a) => deserialize!(&a)?,
                Err(_) => HashMap::new(),
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

        self.storage.store(
            StorableType::BroadcastSet,
            sid,
            self.id(),
            &serialize!(&message_votes)?,
        )?;

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
        bail!("error: no message received enough votes")
    }

    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        leader: ParticipantIdentifier,
    ) -> Result<Vec<Message>> {
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

    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
    ) -> Result<(Option<BroadcastOutput>, Vec<Message>)> {
        let data = BroadcastData::from_message(message)?;
        if data.leader == self.id() {
            return Ok((None, vec![]));
        }
        let output_option = self.process_vote(data, message.id(), message.from())?;
        Ok((output_option, vec![]))
    }
}
