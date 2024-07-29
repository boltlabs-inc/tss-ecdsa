//! Types and methods for our `Message` type and friends.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the functions and definitions for dealing with messages that are
//! passed between participants

use crate::{
    errors::{InternalError, Result},
    protocol::{Identifier, ParticipantIdentifier},
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::{error, instrument, trace};

/////////////////
// Message API //
/////////////////

/// An enum consisting of all message types
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Auxinfo messages
    Auxinfo(AuxinfoMessageType),
    /// Keygen messages
    Keygen(KeygenMessageType),
    /// Tshare messages
    Tshare(TshareMessageType),
    /// Keyrefresh messages
    Keyrefresh(KeyrefreshMessageType),
    /// Presign messages
    Presign(PresignMessageType),
    /// Sign message
    Sign(SignMessageType),
    /// Broadcast messages
    Broadcast(BroadcastMessageType),
}

/// An enum consisting of all auxinfo message types
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuxinfoMessageType {
    /// Signal to self that we're ready to run the protocol
    Ready,
    /// A hash commitment to the public keyshare and associated proofs
    R1CommitHash,
    /// The information committed to in Round 1
    R2Decommit,
    /// A proof of knowledge of the discrete log of the value decommitted in
    /// Round 2
    R3Proof,
}

/// An enum consisting of all keygen message types
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeygenMessageType {
    /// Signal to self that we're ready to run the protocol
    Ready,
    /// A hash commitment to the public keyshare and associated proofs
    R1CommitHash,
    /// The information committed to in Round 1
    R2Decommit,
    /// A proof of knowledge of the discrete log of the value decommitted in
    /// Round 2
    R3Proof,
}

/// An enum consisting of all tshare message types
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum TshareMessageType {
    /// Signal to self that we're ready to run the protocol
    Ready,
    /// A hash commitment to the public keyshare and associated proofs
    R1CommitHash,
    /// The information committed to in Round 1
    R2Decommit,
    /// A proof of knowledge of the discrete log of the value decommitted in
    /// Round 2
    R3Proofs,
    /// The encrypted private share from a participant to another.
    R3PrivateShare,
}

/// An enum consisting of all keyrefresh message types
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyrefreshMessageType {
    /// Signal to self that we're ready to run the protocol
    Ready,
    /// A hash commitment to the public keyshare and associated proofs
    R1CommitHash,
    /// The information committed to in Round 1
    R2Decommit,
    /// A proof of knowledge of the discrete log of the value decommitted in
    /// Round 2
    R3Proofs,
    /// The encrypted private share from a participant to another.
    R3PrivateUpdate,
}

/// An enum consisting of all presign message types
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresignMessageType {
    /// Signal to self that we're ready to run the protocol
    Ready,
    /// First round of presigning
    RoundOne,
    /// Broadcasted portion of the first round
    RoundOneBroadcast,
    /// Second round of presigning
    RoundTwo,
    /// Third round of presigning
    RoundThree,
}

/// Messages sent during the signing protocol
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignMessageType {
    /// Signal to self that we're ready to run the protocol
    Ready,
    /// First (only) round
    RoundOneShare,
}

/// The type of broadcast message this is.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum BroadcastMessageType {
    /// First round: sender sends their message to everyone
    Disperse,
    /// Second round: everyone reflects the message to everyone else
    Redisperse,
}

/// A message that can be posted to (and read from) the communication channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The type of the message
    pub(crate) message_type: MessageType,
    /// The globally unique session identifier that this message belongs to.
    identifier: Identifier,
    /// Which participant this message is coming from.
    from: ParticipantIdentifier,
    /// Which participant this message is addressed to.
    to: ParticipantIdentifier,
    /// The raw bytes for the message, which need to be verified.
    /// This should be a private member of the struct, so that
    /// we require consumers to call the verify() function in
    /// order to extract bytes
    pub(crate) unverified_bytes: Vec<u8>,
}

impl Message {
    /// Creates a new instance of [`Message`].
    #[instrument(skip_all)]
    pub(crate) fn new<T>(
        message_type: MessageType,
        identifier: Identifier,
        from: ParticipantIdentifier,
        to: ParticipantIdentifier,
        unverified_bytes: &T,
    ) -> Result<Self>
    where
        T: Serialize,
    {
        trace!("New message created.");
        Ok(Self {
            message_type,
            identifier,
            from,
            to,
            unverified_bytes: serialize!(unverified_bytes)?,
        })
    }

    /// Creates a new instance of [`Message`] from serialized data.
    /// This was created in order to quickly resolve the bug of extra 8 bytes
    /// while serializing message in broadcast:participant file. It is
    /// recommended to do away with this function in future.
    pub(crate) fn new_from_serialized_data(
        message_type: MessageType,
        identifier: Identifier,
        from: ParticipantIdentifier,
        to: ParticipantIdentifier,
        unverified_bytes: Vec<u8>,
    ) -> Result<Self> {
        trace!("New message created from constructor with serialized data.");
        Ok(Self {
            message_type,
            identifier,
            from,
            to,
            unverified_bytes,
        })
    }

    /// The message type associated with the message.
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// The session identifier associated with the message.
    pub fn id(&self) -> Identifier {
        self.identifier
    }

    /// The participant that sent this message.
    pub fn from(&self) -> ParticipantIdentifier {
        self.from
    }

    /// The participant that should receive this message.
    pub fn to(&self) -> ParticipantIdentifier {
        self.to
    }

    /// Check if the message type is correct.
    pub(crate) fn check_type(&self, expected_type: MessageType) -> Result<()> {
        if self.message_type() != expected_type {
            error!(
                "A message was misrouted. Expected {:?}, Got {:?}",
                expected_type,
                self.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }
        Ok(())
    }

    /// Check if the message type is one of the valid options.
    pub(crate) fn check_one_of_type(&self, expected_types: &[MessageType]) -> Result<()> {
        if !expected_types.contains(&self.message_type()) {
            error!(
                "A message was misrouted. Expected one of {:?}, Got {:?}",
                expected_types,
                self.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }
        Ok(())
    }
}
