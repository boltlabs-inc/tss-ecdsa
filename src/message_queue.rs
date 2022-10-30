// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::Result;
use crate::messages::{Message, MessageType};
use crate::protocol::Identifier;
use crate::ParticipantIdentifier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
struct MessageIndex {
    message_type: MessageType,
    identifier: Identifier,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct MessageQueue(HashMap<Vec<u8>, Vec<Message>>);

impl MessageQueue {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    /// Store a message in the MessageQueue.
    pub(crate) fn store(
        &mut self,
        message_type: MessageType,
        identifier: Identifier,
        message: Message,
    ) -> Result<()> {
        let message_index = MessageIndex {
            message_type,
            identifier,
        };
        let key = serialize!(&message_index)?;
        let mut queue = match self.0.remove(&key) {
            Some(a) => a,
            None => vec![],
        };
        queue.push(message);
        self.0.insert(key, queue);
        Ok(())
    }

    /// Retrieve (and remove) all messages of a given type from the MessageQueue.
    pub(crate) fn retrieve_all(
        &mut self,
        message_type: MessageType,
        identifier: Identifier,
    ) -> Result<Vec<Message>> {
        let message_index = MessageIndex {
            message_type,
            identifier,
        };
        let key = serialize!(&message_index)?;
        // delete retrieved messages from storage so that they aren't accidentally processed again
        let queue = match self.0.remove(&key) {
            Some(a) => a,
            None => vec![],
        };
        Ok(queue)
    }

    /// Retrieve (and remove) all messages of a given type from a given sender from the MessageQueue.
    pub(crate) fn retrieve(
        &mut self,
        message_type: MessageType,
        identifier: Identifier,
        sender: ParticipantIdentifier,
    ) -> Result<Vec<Message>> {
        let message_index = MessageIndex {
            message_type,
            identifier,
        };
        let key = serialize!(&message_index)?;
        let queue = match self.0.get_mut(&key) {
            Some(a) => a,
            None => return Ok(vec![]),
        };
        let mut out_messages = Vec::new();
        let mut indexes_to_remove = Vec::new();
        for (i, message) in queue.iter_mut().enumerate() {
            if message.from() == sender {
                indexes_to_remove.push(i);
                out_messages.push(message.clone());
            }
        }
        for i in indexes_to_remove.iter().rev() {
            queue.remove(*i);
        }
        Ok(out_messages)
    }
}
