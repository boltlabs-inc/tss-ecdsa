// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::broadcast::participant::BroadcastTag;
use crate::{
    broadcast::participant::{BroadcastOutput, BroadcastParticipant},
    errors::Result,
    message_queue::MessageQueue,
    messages::{Message, MessageType},
    protocol::ParticipantIdentifier,
    storage::{StorableType, Storage},
    Identifier,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
struct ProgressIndex {
    func_name: String,
    sid: Identifier,
}

pub(crate) trait ProtocolParticipant {
    fn storage(&self) -> &Storage;
    fn storage_mut(&mut self) -> &mut Storage;
    fn id(&self) -> ParticipantIdentifier;

    fn stash_message(&mut self, message: &Message) -> Result<()> {
        let mut message_storage =
            match self
                .storage()
                .retrieve(StorableType::MessageQueue, message.id(), self.id())
            {
                Err(_) => MessageQueue::new(),
                Ok(message_storage_bytes) => deserialize!(&message_storage_bytes)?,
            };
        message_storage.store(message.message_type(), message.id(), message.clone())?;
        let my_id = self.id();
        self.storage_mut().store(
            StorableType::MessageQueue,
            message.id(),
            my_id,
            &serialize!(&message_storage)?,
        )?;
        Ok(())
    }

    fn fetch_messages(
        &mut self,
        message_type: MessageType,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        let mut message_storage = self.get_message_queue(sid)?;
        let messages = message_storage.retrieve_all(message_type, sid)?;
        self.write_message_queue(sid, message_storage)?;
        Ok(messages)
    }

    fn fetch_messages_by_sender(
        &mut self,
        message_type: MessageType,
        sid: Identifier,
        sender: ParticipantIdentifier,
    ) -> Result<Vec<Message>> {
        let mut message_storage = self.get_message_queue(sid)?;
        let messages = message_storage.retrieve(message_type, sid, sender)?;
        self.write_message_queue(sid, message_storage)?;
        Ok(messages)
    }

    fn get_message_queue(&mut self, sid: Identifier) -> Result<MessageQueue> {
        let message_storage =
            match self
                .storage()
                .retrieve(StorableType::MessageQueue, sid, self.id())
            {
                Err(_) => MessageQueue::new(),
                Ok(message_storage_bytes) => deserialize!(&message_storage_bytes)?,
            };
        Ok(message_storage)
    }

    fn write_message_queue(&mut self, sid: Identifier, message_queue: MessageQueue) -> Result<()> {
        let my_id = self.id();
        self.storage_mut().store(
            StorableType::MessageQueue,
            sid,
            my_id,
            &serialize!(&message_queue)?,
        )
    }

    fn write_progress(&mut self, func_name: String, sid: Identifier) -> Result<()> {
        let mut progress_storage =
            match self
                .storage()
                .retrieve(StorableType::ProgressStore, sid, self.id())
            {
                Err(_) => HashMap::new(),
                Ok(progress_storage_bytes) => deserialize!(&progress_storage_bytes)?,
            };
        let key = serialize!(&ProgressIndex { func_name, sid })?;
        let _ = progress_storage.insert(key, true);
        let my_id = self.id();
        self.storage_mut().store(
            StorableType::ProgressStore,
            sid,
            my_id,
            &serialize!(&progress_storage)?,
        )?;
        Ok(())
    }

    fn read_progress(&self, func_name: String, sid: Identifier) -> Result<bool> {
        let progress_storage =
            match self
                .storage()
                .retrieve(StorableType::ProgressStore, sid, self.id())
            {
                Err(_) => HashMap::<Vec<u8>, bool>::new(),
                Ok(progress_storage_bytes) => deserialize!(&progress_storage_bytes)?,
            };
        let key = serialize!(&ProgressIndex { func_name, sid })?;
        let result = match progress_storage.get(&key) {
            None => false,
            Some(value) => *value,
        };
        Ok(result)
    }
}

pub(crate) trait Broadcast {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant;

    fn broadcast<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message_type: &MessageType,
        data: Vec<u8>,
        sid: Identifier,
        tag: BroadcastTag,
    ) -> Result<Vec<Message>> {
        let mut messages =
            self.broadcast_participant()
                .gen_round_one_msgs(rng, message_type, data, sid, tag)?;
        for msg in messages.iter_mut() {
            msg.unverified_bytes = serialize!(msg)?;
            msg.message_type = *message_type;
        }
        Ok(messages)
    }

    fn handle_broadcast<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<(Option<BroadcastOutput>, Vec<Message>)> {
        let message_type = message.message_type;
        let broadcast_input: Message = deserialize!(&message.unverified_bytes)?;
        let (broadcast_option, mut messages) = self
            .broadcast_participant()
            .process_message(rng, &broadcast_input)?;
        for msg in messages.iter_mut() {
            msg.unverified_bytes = serialize!(msg)?;
            msg.message_type = message_type;
        }
        Ok((broadcast_option, messages))
    }
}

#[macro_export]
/// A macro to keep track of which functions have already been run in a given
/// session Must be a self.function() so that we can access storage
macro_rules! run_only_once {
    ($self:ident . $func_name:ident $args:tt, $sid:expr) => {{
        if $self.read_progress(stringify!($func_name).to_string(), $sid)? {
            println!("Attempted to rerun a run_only_once function");
            Ok(vec![])
        } else {
            $self.write_progress(stringify!($func_name).to_string(), $sid)?;
            $self.$func_name$args
        }
    }};
}

#[macro_export]
/// A macro to keep track of which function||tag combos have already been run in
/// a given session
macro_rules! run_only_once_per_tag {
    ($self:ident . $func_name:ident $args:tt, $sid:expr, $tag:expr) => {{
        let tag_str = format!("{:?}", $tag);
        if $self.read_progress(stringify!($func_name).to_string() + &tag_str, $sid)? {
            println!("Attempted to rerun a run_only_once_per_tag function");
            Ok(vec![])
        } else {
            $self.write_progress(stringify!($func_name).to_string(), $sid)?;
            $self.$func_name$args
        }
    }};
}
