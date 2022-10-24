use crate::errors::Result;
use crate::messages::{BroadcastMessageType, Message, MessageType};
use crate::ParticipantIdentifier;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct BroadcastData {
    pub(crate) leader: ParticipantIdentifier,
    pub(crate) tag: String,
    pub(crate) message_type: MessageType,
    pub(crate) data: Vec<u8>,
}

impl BroadcastData {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Broadcast(BroadcastMessageType::Disperse)
            && message.message_type() != MessageType::Broadcast(BroadcastMessageType::Redisperse)
        {
            return bail!("Wrong message type, expected MessageType::Broadcast(BroadcastMessageType::Disperse) or ...Redisperse");
        }
        let broadcast_data: BroadcastData = deserialize!(&message.unverified_bytes)?;
        Ok(broadcast_data)
    }
}
