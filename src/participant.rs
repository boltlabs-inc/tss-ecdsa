// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module contains [`ProtocolParticipant`], the core trait for
//! implementing the various sub-protocols required by `tss-ecsda`.

use crate::{
    broadcast::participant::{BroadcastParticipant, BroadcastTag},
    errors::{InternalError, Result},
    local_storage::{storage as local_storage, LocalStorage, TypeTag},
    messages::{Message, MessageType},
    protocol::{ParticipantIdentifier, ProtocolType},
    Identifier,
};
use rand::{CryptoRng, RngCore};
use std::fmt::Debug;
use tracing::error;

/// Possible outcomes from processing one or more messages.
///
/// Processing an individual message causes various outcomes in a protocol
/// execution. Depending on what other state a [`ProtocolParticipant`] has, a
/// message might be be stored for later processing or partially processed
/// without completing the protocol round. Alternately, it can trigger
/// completion of a protocol round, which may produce messages to be sent to
/// other participants, an output (if the round was the final round), or both.
pub enum ProcessOutcome<O> {
    /// The message was not fully processed; we need more inputs to continue.
    Incomplete,
    /// The message was processed successfully but the subprotocol isn't done.
    Processed(Vec<Message>),
    /// The subprotocol is done for this participant but there are still
    /// messages to send to others.
    TerminatedForThisParticipant(O, Vec<Message>),
    /// The entire subprotocol is done and there are no more messages to send.
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

    /// Convert the caller into a `ProcessOutcome` with a different output type.
    ///
    /// This method handles both the output and message components of the
    /// calling outcome:
    /// - messages are copied as-is into the returned outcome
    /// - if there's an output, it's processed by the handler function
    ///
    /// The handler function must be a method on an
    /// [`InnerProtocolParticipant`], and must produce the correct outcome
    /// type for that [`InnerProtocolParticipant`].
    pub(crate) fn convert<P, F, R>(
        self,
        participant: &mut P,
        mut handle_output: F,
        rng: &mut R,
        storage: &P::Input,
    ) -> Result<ProcessOutcome<P::Output>>
    where
        P: InnerProtocolParticipant,
        F: FnMut(&mut P, &mut R, &O, &P::Input) -> Result<ProcessOutcome<P::Output>>,
        R: CryptoRng + RngCore,
    {
        let (output, messages) = self.into_parts();
        let outcome = match output {
            Some(o) => handle_output(participant, rng, &o, storage)?,
            None => ProcessOutcome::Incomplete,
        };
        Ok(outcome.with_messages(messages))
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

    /// Collect a set of `ProcessOutcome`s into a single outcome.
    ///
    /// This collects all of the messages into a single set, and makes sure that
    /// there's no more than one output specified among all the outcomes.
    pub(crate) fn collect(outcomes: Vec<Self>) -> Result<Self> {
        Self::Incomplete.consolidate(outcomes)
    }

    /// Collect a set of `ProcessOutcome`s into a single outcome with the given
    /// `Message`s.
    ///
    /// This collects all of the messages into a single set, including messages
    /// from the outcome set and from the additional messages, and makes
    /// sure that there's no more than one output specified among all the
    /// outcomes.
    pub(crate) fn collect_with_messages(
        outcomes: Vec<Self>,
        messages: Vec<Message>,
    ) -> Result<Self> {
        Ok(Self::collect(outcomes)?.with_messages(messages))
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

    /// Combine a `ProcessOutcome` with an additional set of [`Message`]s.
    pub(crate) fn with_messages(self, mut messages: Vec<Message>) -> Self {
        let (output, mut original_messages) = self.into_parts();
        original_messages.append(&mut messages);
        Self::from(output, original_messages)
    }
}

/// These are the public-facing methods that must be implemented for a given
/// protocol.
pub trait ProtocolParticipant {
    /// Input type for a new protocol instance.
    type Input: Debug + Clone;
    /// Output type of a successful protocol execution.
    type Output: Debug;
    /// Type to determine status of protocol execution.
    type Status: Debug + PartialEq;

    /// Get the type of a "ready" message, signalling that a participant
    /// is ready to begin protocol execution.
    fn ready_type() -> MessageType;

    /// Define which protocol this implements.
    fn protocol_type() -> ProtocolType;

    /// Create a new [`ProtocolParticipant`] from the given ids.
    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Self;

    /// Return the participant id
    fn id(&self) -> ParticipantIdentifier;

    /// Return other Participant ids apart from the current one
    fn other_ids(&self) -> &Vec<ParticipantIdentifier>;

    /// Returns a list of all participant IDs, including `self`'s.
    fn all_participants(&self) -> Vec<ParticipantIdentifier> {
        let mut participant = self.other_ids().clone();
        participant.push(self.id());
        participant
    }

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
    /// - The message was not parseable
    /// - The message does not belong to this participant or session
    /// - The message contained invalid values and a protocol check failed
    ///
    /// # Assumptions
    /// This method can safely assume (and thus doesn't need to check) the
    /// following:
    /// - The message SID matches the participant's SID.
    /// - The recipient ID matches the participant's ID.
    /// - The message type belongs to the correct protocol.
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Self::Input,
    ) -> Result<ProcessOutcome<Self::Output>>;

    /// The status of the protocol execution.
    fn status(&self) -> &Self::Status;

    /// The session identifier for the current session
    fn sid(&self) -> Identifier;

    /// The input of the current session
    fn input(&self) -> &Self::Input;
}

pub(crate) trait InnerProtocolParticipant: ProtocolParticipant {
    /// Context type that captures all relevant auxiliary information to the
    /// proof.
    type Context;

    /// Returns a reference to the participant's context.
    fn retrieve_context(&self) -> Self::Context;

    /// Returns a reference to the [`LocalStorage`] associated with this
    /// protocol.
    fn local_storage(&self) -> &LocalStorage;
    /// Returns a mutable reference to the [`LocalStorage`] associated with this
    /// protocol.
    fn local_storage_mut(&mut self) -> &mut LocalStorage;

    /// Process a `ready` message: tell other participants that we're ready and
    /// see if all others have also reported that they are ready.
    fn process_ready_message<T: TypeTag<Value = ()>>(
        &mut self,
        message: &Message,
    ) -> Result<(ProcessOutcome<Self::Output>, bool)> {
        self.local_storage_mut().store::<T>(message.from(), ());
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
            .contains_for_all_ids::<T>(&self.all_participants());

        Ok((self_initiated_outcome, is_ready))
    }

    /// Retrieves an item from [`LocalStorage`] associated with the given
    /// [`TypeTag`]. If the entry is not found in storage, we populate the
    /// storage with its [`Default`].
    fn get_from_storage<T: TypeTag>(&mut self) -> Result<&mut T::Value>
    where
        T::Value: Default,
    {
        let pid = self.id();
        if self.local_storage_mut().retrieve_mut::<T>(pid).is_err() {
            self.local_storage_mut().store::<T>(pid, Default::default());
        }
        self.local_storage_mut().retrieve_mut::<T>(pid)
    }

    /// Store [`Message`] in the message queue.
    fn stash_message(&mut self, message: &Message) -> Result<()> {
        let message_storage = self.get_from_storage::<local_storage::MessageQueue>()?;
        message_storage.store(message.clone())?;
        Ok(())
    }
    /// Fetch (and remove) all [`Message`]s matching the given [`MessageType`].
    /// If no messages are found, return an empty [`Vec`].
    fn fetch_messages(&mut self, message_type: MessageType) -> Result<Vec<Message>> {
        let message_storage = self.get_from_storage::<local_storage::MessageQueue>()?;
        Ok(message_storage.retrieve_all(message_type))
    }
    /// Fetch (and remove) all [`Message`]s matching the given [`MessageType`]
    /// and [`ParticipantIdentifier`]. If no messages are found, return an empty
    /// [`Vec`].
    fn fetch_messages_by_sender(
        &mut self,
        message_type: MessageType,
        sender: ParticipantIdentifier,
    ) -> Result<Vec<Message>> {
        let message_storage = self.get_from_storage::<local_storage::MessageQueue>()?;
        Ok(message_storage.retrieve(message_type, sender))
    }

    fn write_progress(&mut self, func_name: String) -> Result<()> {
        let progress_storage = self.get_from_storage::<local_storage::ProgressStore>()?;
        let _ = progress_storage.insert(func_name);
        Ok(())
    }

    fn read_progress(&mut self, func_name: String) -> Result<bool> {
        let progress_storage = self.get_from_storage::<local_storage::ProgressStore>()?;
        Ok(progress_storage.get(&func_name).is_some())
    }
}

pub(crate) trait Broadcast {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant;
    ///`sid` corresponds to a unique session identifier.
    fn broadcast<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message_type: MessageType,
        data: Vec<u8>,
        sid: Identifier,
        tag: BroadcastTag,
    ) -> Result<Vec<Message>> {
        let mut messages =
            self.broadcast_participant()
                .gen_round_one_msgs(rng, message_type, data, sid, tag)?;
        for msg in &mut messages {
            msg.unverified_bytes = serialize!(msg)?;
            msg.message_type = message_type;
        }
        Ok(messages)
    }

    fn handle_broadcast<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<BroadcastParticipant as ProtocolParticipant>::Output>> {
        // Broadcast messages are handled by wrapping the broadcast protocol messages
        // into calling-protocol-specific wrappers. To handle a broadcast message, we
        // need to first unwrap the broadcast message...
        let message_type = message.message_type;
        let broadcast_input: Message = deserialize!(&message.unverified_bytes)?;

        let outcome = self
            .broadcast_participant()
            .process_message(rng, &broadcast_input, &())?;

        // ...and then re-wrap the output messages.
        let (output, mut messages) = outcome.into_parts();
        for msg in &mut messages {
            msg.unverified_bytes = serialize!(msg)?;
            msg.message_type = message_type;
        }
        Ok(ProcessOutcome::from(output, messages))
    }
}

#[macro_export]
/// A macro to keep track of which functions have already been run in a given
/// session. Must be a `self.function()` so that we can access local storage.
macro_rules! run_only_once {
    ($self:ident . $func_name:ident $args:tt) => {{
        if $self.read_progress(stringify!($func_name).to_string())? {
            Ok(vec![])
        } else {
            $self.write_progress(stringify!($func_name).to_string())?;
            $self.$func_name$args
        }
    }};
}

#[macro_export]
/// A macro to keep track of which function||tag combos have already been run in
/// a given session
macro_rules! run_only_once_per_tag {
    ($self:ident . $func_name:ident $args:tt, $tag:expr) => {{
        let tag_str = format!("{:?}", $tag);
        if $self.read_progress(stringify!($func_name).to_string() + &tag_str)? {
            Ok(vec![])
        } else {
            $self.write_progress(stringify!($func_name).to_string())?;
            $self.$func_name$args
        }
    }};
}
