// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The `MessageQueue` type for storing and retrieving a queue of messages.
//!
//! [`MessageQueue`] provides a simple means of storing and retrieving messages
//! associated with a given [`MessageType`]. Messages can be retrieved either
//! all at once using [`MessageQueue::retrieve_all`] or associated with a given
//! [`ParticipantIdentifier`] using [`MessageQueue::retrieve`].

use crate::{
    errors::Result,
    messages::{Message, MessageType},
    ParticipantIdentifier,
};
use std::collections::HashMap;

/// A type for storing a queue of [`Message`]s by [`MessageType`].
#[derive(Clone, Default)]
pub(crate) struct MessageQueue(HashMap<MessageType, Vec<Message>>);

impl MessageQueue {
    /// Store a message by its [`MessageType`].
    pub(crate) fn store(&mut self, message: Message) -> Result<()> {
        self.0
            .entry(message.message_type())
            .or_default()
            .push(message);
        Ok(())
    }

    /// Retrieve (and remove) all [`Message`]s of a given [`MessageType`].
    ///
    /// If the given [`MessageType`] is not found, an empty [`Vec`] is returned.
    pub(crate) fn retrieve_all_of_type(&mut self, message_type: MessageType) -> Vec<Message> {
        self.do_retrieve(message_type, None)
    }

    /// Retrieve (and remove) all [`Message`]s from the [`MessageQueue`].
    ///
    /// If no messages are found, an empty [`Vec`] is returned.
    pub(crate) fn retrieve_all(&mut self) -> Vec<Message> {
        self.0.drain().flat_map(|(_key, value)| value).collect()
    }

    /// Retrieve (and remove) all [`Message`]s of a given [`MessageType`] associated
    /// with the given [`ParticipantIdentifier`].
    ///
    /// If the given [`MessageType`] is not found, an empty [`Vec`] is returned.
    pub(crate) fn retrieve(
        &mut self,
        message_type: MessageType,
        sender: ParticipantIdentifier,
    ) -> Vec<Message> {
        self.do_retrieve(message_type, Some(sender))
    }

    fn do_retrieve(
        &mut self,
        message_type: MessageType,
        sender: Option<ParticipantIdentifier>,
    ) -> Vec<Message> {
        // delete retrieved messages from storage so that they aren't accidentally
        // processed again.
        let queue = self.0.remove(&message_type).unwrap_or_default();

        match sender {
            None => queue,
            Some(sender) => {
                // separate messages we want to retrieve
                let (out, new_queue): (Vec<_>, Vec<_>) =
                    queue.into_iter().partition(|msg| msg.from() == sender);

                // re-add updated queue
                if !new_queue.is_empty() {
                    let _ = self.0.insert(message_type, new_queue);
                }
                out
            }
        }
    }
}
