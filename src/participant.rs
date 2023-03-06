// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::Result,
    message_queue::MessageQueue,
    messages::{Message, MessageType},
    protocol::ParticipantIdentifier,
    storage::{PersistentStorageType, Storage},
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

/// Possible outcomes from processing one or more messages.
///
/// Processing an individual message causes various outcomes in a protocol
/// execution. Depending on what other state a [`ProtocolParticipant`] has, a
/// message might be be stored for later processing or partially processed
/// without completing the protocol round. Alternately, it can trigger
/// completion of a protocol round, which may produce messages to be sent to
/// other participants, an output (if the round was the final round), or both.
pub(crate) enum ProcessOutcome<O> {
    // The message was not fully processed; we need more inputs to continue.
    Incomplete,
    // The message was processed successfully but the subprotocol isn't done.
    Processed(Vec<Message>),
    // The subprotocol is done for this participant but there are still messages to send to
    // others.
    TerminatedForThisParticipant(O, Vec<Message>),
    // The entire subprotocol is done and there are no more messages to send.
    Terminated(O),
}

impl<O> ProcessOutcome<O> {
    /// Create a [`ProcessOutcome`] from an optional output and a set of
    /// outgoing messages.
    pub(crate) fn from(output: Option<O>, messages: Vec<Message>) -> Self {
        match (output, messages.len()) {
            (None, 0) => Self::Incomplete,
            (None, _) => Self::Processed(messages),
            (Some(o), 0) => Self::Terminated(o),
            (Some(o), _) => Self::TerminatedForThisParticipant(o, messages),
        }
    }

    /// Extract the outgoing messages from the [`ProcessOutcome`].
    ///
    /// This method drops the outcome, if it exists, so it's no longer
    /// accessible.
    pub(crate) fn into_messages(self) -> Vec<Message> {
        match self {
            Self::Incomplete | Self::Terminated(_) => Vec::new(),
            Self::Processed(messages) => messages,
            Self::TerminatedForThisParticipant(_, messages) => messages,
        }
    }

    /// Convert the [`ProcessOutcome`] into its constituent parts.
    pub(crate) fn into_parts(self) -> (Option<O>, Vec<Message>) {
        match self {
            Self::Incomplete => (None, Vec::new()),
            Self::Processed(msgs) => (None, msgs),
            Self::TerminatedForThisParticipant(output, msgs) => (Some(output), msgs),
            Self::Terminated(output) => (Some(output), Vec::new()),
        }
    }
}

pub(crate) trait ProtocolParticipant {
    /// Output type of a successful protocol execution.
    type Output;

    fn storage(&self) -> &Storage;
    fn storage_mut(&mut self) -> &mut Storage;
    fn id(&self) -> ParticipantIdentifier;

    /// Process an incoming message.
    ///
    /// This method should parse the message, do any immediate per-message
    /// processing, and if all necessary messages have been received,
    /// compute a round of the protocol.
    /// In some cases, this method will process other stored messages that have
    /// become usable by the processing of the given message. The
    /// `ProcessOutcome` is the consolidated outputs of all processed
    /// messages.
    ///
    /// Potential failure cases:
    /// - `Storage` did not contain the necessary preliminary artifacts (TODO
    ///   #180: pass inputs as parameters, instead)
    /// - The message was not parseable
    /// - The message contained invalid values and a protocol check failed
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<ProcessOutcome<Self::Output>>;

    fn stash_message(&mut self, message: &Message) -> Result<()> {
        let mut message_storage: MessageQueue = self
            .storage()
            .retrieve(PersistentStorageType::MessageQueue, message.id(), self.id())
            .unwrap_or_default();
        message_storage.store(message.message_type(), message.id(), message.clone())?;
        let my_id = self.id();
        self.storage_mut().store(
            PersistentStorageType::MessageQueue,
            message.id(),
            my_id,
            &message_storage,
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
        let message_storage: MessageQueue = self
            .storage()
            .retrieve(PersistentStorageType::MessageQueue, sid, self.id())
            .unwrap_or_default();
        Ok(message_storage)
    }

    fn write_message_queue(&mut self, sid: Identifier, message_queue: MessageQueue) -> Result<()> {
        let my_id = self.id();
        self.storage_mut().store(
            PersistentStorageType::MessageQueue,
            sid,
            my_id,
            &message_queue,
        )
    }

    fn write_progress(&mut self, func_name: String, sid: Identifier) -> Result<()> {
        let mut progress_storage: HashMap<Vec<u8>, bool> = self
            .storage()
            .retrieve(PersistentStorageType::ProgressStore, sid, self.id())
            .unwrap_or_default();
        let key = serialize!(&ProgressIndex { func_name, sid })?;
        let _ = progress_storage.insert(key, true);
        let my_id = self.id();
        self.storage_mut().store(
            PersistentStorageType::ProgressStore,
            sid,
            my_id,
            &progress_storage,
        )?;
        Ok(())
    }

    fn read_progress(&self, func_name: String, sid: Identifier) -> Result<bool> {
        let progress_storage: HashMap<Vec<u8>, bool> = self
            .storage()
            .retrieve(PersistentStorageType::ProgressStore, sid, self.id())
            .unwrap_or_default();
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

        // Make some empty storage to satisfy the trait. TODO #180: remove this.
        let mut empty_storage = Storage::new();

        let outcome = self.broadcast_participant().process_message(
            rng,
            &broadcast_input,
            &mut empty_storage,
        )?;

        let (output, mut messages) = outcome.into_parts();
        for msg in messages.iter_mut() {
            msg.unverified_bytes = serialize!(msg)?;
            msg.message_type = message_type;
        }
        Ok((output, messages))
    }
}

#[macro_export]
/// A macro to keep track of which functions have already been run in a given
/// session Must be a self.function() so that we can access storage
macro_rules! run_only_once {
    ($self:ident . $func_name:ident $args:tt, $sid:expr) => {{
        if $self.read_progress(stringify!($func_name).to_string(), $sid)? {
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
            Ok(vec![])
        } else {
            $self.write_progress(stringify!($func_name).to_string(), $sid)?;
            $self.$func_name$args
        }
    }};
}
