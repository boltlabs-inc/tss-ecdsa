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
    curve::CurveTrait,
    errors::{InternalError, Result},
    local_storage::{storage as local_storage, LocalStorage, TypeTag},
    messages::{Message, MessageType},
    protocol::{ParticipantIdentifier, ProtocolType},
    Identifier,
};
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use std::fmt::Debug;
use tracing::{error, warn};

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
    ) -> Result<ProcessOutcome<P::Output>>
    where
        P: InnerProtocolParticipant,
        F: FnMut(&mut P, &mut R, O) -> Result<ProcessOutcome<P::Output>>,
        R: CryptoRng + RngCore,
    {
        let (output, messages) = self.into_parts();
        let outcome = match output {
            Some(o) => handle_output(participant, rng, o)?,
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
    type Input: Debug;
    /// Output type of a successful protocol execution.
    type Output: Debug;

    /// Get the type of a "ready" message, signalling that a participant
    /// is ready to begin protocol execution.
    fn ready_type() -> MessageType;

    /// Define which protocol this implements.
    fn protocol_type() -> ProtocolType;

    /// Create a new [`ProtocolParticipant`] from the given ids.
    ///
    /// **Assumption**: This method _does not_ validate the
    /// [`ParticipantIdentifier`]s. It assumes that they comprise a unique
    /// set and that there are a valid number of participants for a session.
    ///
    /// This method _does_ validate the input, checking any appropriate
    /// constraints on its type and its relationship to the participant set
    /// (for example, it may check that the input contains one field for
    /// each participant).
    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self>
    where
        Self: Sized;

    /// Return the participant id
    fn id(&self) -> ParticipantIdentifier;

    /// Return other Participant ids apart from the current one
    fn other_ids(&self) -> &[ParticipantIdentifier];

    /// Returns a list of all participant IDs, including `self`'s.
    fn all_participants(&self) -> Vec<ParticipantIdentifier> {
        let mut participant = self.other_ids().to_owned();
        participant.push(self.id());
        participant.to_vec()
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
    ) -> Result<ProcessOutcome<Self::Output>>;

    /// The status of the protocol execution.
    fn status(&self) -> &Status;

    /// The session identifier for the current session
    fn sid(&self) -> Identifier;
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

    /// Returns a Result[`Vec<Message>`] which are intended for the other
    /// participants.
    fn message_for_other_participants<T: Serialize>(
        &self,
        message_type: MessageType,
        data: T,
    ) -> Result<Vec<Message>> {
        self.other_ids()
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    message_type,
                    self.sid(),
                    self.id(),
                    other_participant_id,
                    &data,
                )
            })
            .collect()
    }

    /// Process a `ready` message: If it came from another Participant, reject
    /// it. Once ready, process all messages that were received before
    /// ready.
    fn process_ready_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        // First, make sure the message actually came from you.
        if message.from() != self.id() {
            error!(
                "Received a Ready message from {}, but Ready should only be sent to yourself!",
                message.from()
            );
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        // Process any messages that had been received before the Ready signal
        let banked_messages = self.fetch_all_messages()?;

        // Ensure our status is in the right state.
        let status = self.status_mut();
        if status != &Status::NotReady {
            return Err(InternalError::UnexpectedStatus(status.clone()));
        }
        // And update to _ready_.
        *status = Status::Initialized;

        let outcomes = banked_messages
            .iter()
            .map(|m| self.process_message(rng, m))
            .collect::<Result<Vec<_>>>()?;

        ProcessOutcome::collect(outcomes)
    }

    /// Retrieves an item from [`LocalStorage`] associated with the given
    /// [`TypeTag`]. If the entry is not found in storage, we populate the
    /// storage with its [`Default`].
    fn get_from_storage<T: TypeTag>(&mut self) -> Result<&mut T::Value>
    where
        T::Value: Default,
    {
        let pid = self.id();
        if !self.local_storage_mut().contains::<T>(pid) {
            self.local_storage_mut().store::<T>(pid, Default::default());
        }
        self.local_storage_mut()
            .retrieve_mut::<T>(pid)
            .ok_or_else(|| {
                error!(
                    "Failed to retrieve {} mutably from storage",
                    std::any::type_name::<T::Value>()
                );
                InternalError::InternalInvariantFailed
            })
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
        Ok(message_storage.retrieve_all_of_type(message_type))
    }

    /// Fetch (and remove) all [`Message`]s of any [`MessageType`].
    /// If no messages are found, return an empty [`Vec`].
    fn fetch_all_messages(&mut self) -> Result<Vec<Message>> {
        let message_storage = self.get_from_storage::<local_storage::MessageQueue>()?;
        Ok(message_storage.retrieve_all())
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

    fn check_for_duplicate_msg<T: TypeTag>(&self, from: ParticipantIdentifier) -> Result<()> {
        if self.local_storage().contains::<T>(from) {
            warn!(
                "Received duplicate message from {:?} of type {}",
                from,
                std::any::type_name::<T>()
            );
            Err(InternalError::DuplicateMessage(from))
        } else {
            Ok(())
        }
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

    fn status_mut(&mut self) -> &mut Status;
}

pub(crate) trait Broadcast<C: CurveTrait> {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant<C>;
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
    ) -> Result<ProcessOutcome<<BroadcastParticipant<C> as ProtocolParticipant>::Output>> {
        // Broadcast messages are handled by wrapping the broadcast protocol messages
        // into calling-protocol-specific wrappers. To handle a broadcast message, we
        // need to first unwrap the broadcast message...
        let message_type = message.message_type;
        let broadcast_input: Message = deserialize!(&message.unverified_bytes)?;

        let outcome = self
            .broadcast_participant()
            .process_message(rng, &broadcast_input)?;

        // ...and then re-wrap the output messages.
        let (output, mut messages) = outcome.into_parts();
        for msg in &mut messages {
            msg.unverified_bytes = serialize!(msg)?;
            msg.message_type = message_type;
        }
        Ok(ProcessOutcome::from(output, messages))
    }
}

/// Protocol status for implementors of [`ProtocolParticipant`].
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Status {
    /// Participant is created but has not received a ready message from self.
    NotReady,
    /// Participant received a ready message and is executing the protocol.
    Initialized,
    /// Participant finished the protocol.
    TerminatedSuccessfully,
    /// Participant received a ready message and is running presign.
    ///
    /// This variant is used by
    /// [`InteractiveSignParticipant`](crate::sign::InteractiveSignParticipant)
    RunningPresign,
    /// Participant received a ready message and is running tshare.
    ///
    /// This variant is used by
    /// [`InteractiveSignParticipant`](crate::sign::InteractiveSignParticipant)
    RunningSign,
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
    ///
    /// This variant is used by [`BroadcastParticipant`]
    ParticipantCompletedBroadcast(Vec<ParticipantIdentifier>),
}

impl Status {
    pub(crate) fn is_ready(&self) -> bool {
        self != &Status::NotReady
    }
}

#[macro_export]
/// A macro to keep track of which functions have already been run in a given
/// session. Mst be a `self.function()` so that we can access local storage.
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
