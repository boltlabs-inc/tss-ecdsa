// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::participant::BroadcastTag,
    errors::{InternalError, Result},
    messages::{BroadcastMessageType, Message, MessageType},
    ParticipantIdentifier,
};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BroadcastData {
    pub(crate) leader: ParticipantIdentifier,
    pub(crate) tag: BroadcastTag,
    pub(crate) message_type: MessageType,
    pub(crate) data: Vec<u8>,
}

impl BroadcastData {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Broadcast(BroadcastMessageType::Disperse)
            && message.message_type() != MessageType::Broadcast(BroadcastMessageType::Redisperse)
        {
            error!(
                "Incorrect MessageType given to Broadcast Handler. Got: {:?}",
                message.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }
        let broadcast_data: BroadcastData = deserialize!(&message.unverified_bytes)?;
        Ok(broadcast_data)
    }
}
