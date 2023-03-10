// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{InternalError, Result},
    local_storage::{storage as local_storage, LocalStorage, TypeTag},
    messages::{Message, MessageType},
    protocol::ParticipantIdentifier,
    storage::Storage,
    Identifier,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;

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

impl<O> Debug for ProcessOutcome<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let descriptor = match self {
            ProcessOutcome::Incomplete => "Incomplete",
            ProcessOutcome::Processed(_) => "Processed",
            ProcessOutcome::Terminated(_) => "Terminated",
            ProcessOutcome::TerminatedForThisParticipant(_, _) => "Terminated for this participant",
        };
        write!(f, "ProcessOutcome::{descriptor}")
    }
}

impl<O> ProcessOutcome<O>
where
    O: std::fmt::Debug,
{
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

    /// Consolidate a set of `ProcessOutcome`s, including `self`, into a single
    /// outcome.
    ///
    /// This collects all of the messages into a single set, and makes sure that
    /// there's no more than one output specified among all the outcomes.
    pub(crate) fn consolidate(self, outcomes: Vec<Self>) -> Result<Self> {
        let (outputs, messages): (Vec<_>, Vec<_>) = std::iter::once(self)
            .chain(outcomes)
            .map(Self::into_parts)
            .unzip();

        // Get the first output, if it exists.
        let mut actual_outputs = outputs.into_iter().flatten();
        let output = actual_outputs.next();
        // Throw an error if there's more than one
        if actual_outputs.next().is_some() {
            error!(
                "Produced more than one output in a single session. {:?}",
                actual_outputs
            );
            Err(InternalError::InternalInvariantFailed)?
        }

        let messages = messages.into_iter().flatten().collect();

        Ok(ProcessOutcome::from(output, messages))
    }
}

pub(crate) trait ProtocolParticipant {
    /// Output type of a successful protocol execution.
    type Output;

    /// Returns a reference to the [`LocalStorage`] associated with this
    /// protocol.
    fn local_storage(&self) -> &LocalStorage;
    /// Returns a mutable reference to the [`LocalStorage`] associated with this
    /// protocol.
    fn local_storage_mut(&mut self) -> &mut LocalStorage;
    fn id(&self) -> ParticipantIdentifier;
    fn other_ids(&self) -> &Vec<ParticipantIdentifier>;

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

    /// Returns a list of all participant IDs, including `self`'s.
    fn all_participants(&self) -> Vec<ParticipantIdentifier> {
        let mut participant = self.other_ids().clone();
        participant.push(self.id());
        participant
    }

    /// Process a `ready` message: tell other participants that we're ready and
    /// see if all others have also reported that they are ready.
    fn process_ready_message<T: TypeTag<Value = ()>>(
        &mut self,
        message: &Message,
    ) -> Result<(ProcessOutcome<Self::Output>, bool)> {
        self.local_storage_mut()
            .store::<T>(message.id(), message.from(), ());
        // If message came from self, then tell the other participants that we are ready
        let self_initiated_outcome = if message.from() == self.id() {
            let messages = self
                .other_ids()
                .iter()
                .map(|other_id| {
                    Message::new(
                        message.message_type(),
                        message.id(),
                        self.id(),
                        *other_id,
                        &[],
                    )
                })
                .collect();
            ProcessOutcome::Processed(messages)
        } else {
            ProcessOutcome::Incomplete
        };

        // Make sure that all parties are ready before proceeding
        let is_ready = self
            .local_storage()
            .contains_for_all_ids::<T>(message.id(), &self.all_participants());

        Ok((self_initiated_outcome, is_ready))
    }

    /// Retrieves an item from [`LocalStorage`] associated with the given
    /// [`TypeTag`]. If the entry is not found in storage, we populate the
    /// storage with its [`Default`].
    fn get_from_storage<T: TypeTag>(&mut self, id: Identifier) -> Result<&mut T::Value>
    where
        T::Value: Default,
    {
        let pid = self.id();
        if self.local_storage_mut().retrieve_mut::<T>(id, pid).is_err() {
            self.local_storage_mut()
                .store::<T>(id, pid, Default::default());
        }
        self.local_storage_mut().retrieve_mut::<T>(id, pid)
    }

    fn stash_message(&mut self, message: &Message) -> Result<()> {
        let message_storage = self.get_from_storage::<local_storage::MessageQueue>(message.id())?;
        message_storage.store(message.message_type(), message.id(), message.clone())?;
        Ok(())
    }

    fn fetch_messages(
        &mut self,
        message_type: MessageType,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        let message_storage = self.get_from_storage::<local_storage::MessageQueue>(sid)?;
        let messages = message_storage.retrieve_all(message_type, sid)?;
        Ok(messages)
    }

    fn fetch_messages_by_sender(
        &mut self,
        message_type: MessageType,
        sid: Identifier,
        sender: ParticipantIdentifier,
    ) -> Result<Vec<Message>> {
        let message_storage = self.get_from_storage::<local_storage::MessageQueue>(sid)?;
        let messages = message_storage.retrieve(message_type, sid, sender)?;
        Ok(messages)
    }

    fn write_progress(&mut self, func_name: String, sid: Identifier) -> Result<()> {
        let key = serialize!(&ProgressIndex { func_name, sid })?;
        let progress_storage = self.get_from_storage::<local_storage::ProgressStore>(sid)?;
        let _ = progress_storage.insert(key, true);
        Ok(())
    }

    fn read_progress(&mut self, func_name: String, sid: Identifier) -> Result<bool> {
        let key = serialize!(&ProgressIndex { func_name, sid })?;
        let progress_storage = self.get_from_storage::<local_storage::ProgressStore>(sid)?;
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
