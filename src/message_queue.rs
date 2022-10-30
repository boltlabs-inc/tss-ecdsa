// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::Result,
    messages::{Message, MessageType},
    protocol::Identifier,
    ParticipantIdentifier,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};

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
        let key = Self::get_key(message_type, identifier)?;
        self.0.entry(key).or_default().push(message);
        Ok(())
    }

    /// Retrieve (and remove) all messages of a given type from the
    /// MessageQueue.
    pub(crate) fn retrieve_all(
        &mut self,
        message_type: MessageType,
        identifier: Identifier,
    ) -> Result<Vec<Message>> {
        self.do_retrieve(message_type, identifier, None)
    }

    /// Retrieve (and remove) all messages of a given type from a given sender
    /// from the MessageQueue.
    pub(crate) fn retrieve(
        &mut self,
        message_type: MessageType,
        identifier: Identifier,
        sender: ParticipantIdentifier,
    ) -> Result<Vec<Message>> {
        self.do_retrieve(message_type, identifier, Some(sender))
    }

    fn do_retrieve(
        &mut self,
        message_type: MessageType,
        identifier: Identifier,
        sender: Option<ParticipantIdentifier>,
    ) -> Result<Vec<Message>> {
        let key = Self::get_key(message_type, identifier)?;
        // delete retrieved messages from storage so that they aren't accidentally
        // processed again.
        let queue = self.0.remove(&key).unwrap_or_default();

        match sender {
            None => Ok(queue),
            Some(sender) => {
                // separate messages we want to retrieve
                let (out, new_queue): (Vec<_>, Vec<_>) =
                    queue.into_iter().partition(|msg| msg.from() == sender);

                // re-add updated queue
                if !new_queue.is_empty() {
                    let _ = self.0.insert(key, new_queue);
                }
                Ok(out)
            }
        }
    }

    fn get_key(message_type: MessageType, identifier: Identifier) -> Result<Vec<u8>> {
        let message_index = MessageIndex {
            message_type,
            identifier,
        };
        Ok(serialize!(&message_index)?)
    }
}
