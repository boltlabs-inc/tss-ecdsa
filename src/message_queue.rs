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
    /// Store a message by the given [`MessageType`].
    pub(crate) fn store(&mut self, message_type: MessageType, message: Message) -> Result<()> {
        self.0.entry(message_type).or_default().push(message);
        Ok(())
    }

    /// Retrieve (and remove) all messages of a given [`MessageType`].
    pub(crate) fn retrieve_all(&mut self, message_type: MessageType) -> Result<Vec<Message>> {
        self.do_retrieve(message_type, None)
    }

    /// Retrieve (and remove) all messages of a given [`MessageType`] associated
    /// with the given [`ParticipantIdentifier`].
    pub(crate) fn retrieve(
        &mut self,
        message_type: MessageType,
        sender: ParticipantIdentifier,
    ) -> Result<Vec<Message>> {
        self.do_retrieve(message_type, Some(sender))
    }

    fn do_retrieve(
        &mut self,
        message_type: MessageType,
        sender: Option<ParticipantIdentifier>,
    ) -> Result<Vec<Message>> {
        // delete retrieved messages from storage so that they aren't accidentally
        // processed again.
        let queue = self.0.remove(&message_type).unwrap_or_default();

        match sender {
            None => Ok(queue),
            Some(sender) => {
                // separate messages we want to retrieve
                let (out, new_queue): (Vec<_>, Vec<_>) =
                    queue.into_iter().partition(|msg| msg.from() == sender);

                // re-add updated queue
                if !new_queue.is_empty() {
                    let _ = self.0.insert(message_type, new_queue);
                }
                Ok(out)
            }
        }
    }
}
