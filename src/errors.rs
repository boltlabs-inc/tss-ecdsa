// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A list of error types which are produced during an execution of the protocol
use crate::{participant::Status, ParticipantIdentifier};
use core::fmt::Debug;
use thiserror::Error;

/// The default Result type used in this crate
pub type Result<T> = std::result::Result<T, InternalError>;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Clone, Eq, PartialEq, Error, Debug)]
#[allow(missing_docs)]
pub enum InternalError {
    #[error("Caller error: {0}")]
    CallingApplicationMistake(#[from] CallerError),
    #[error("Serialization Error")]
    Serialization,
    #[error("Some player sent a message which does not match the protocol specification: {0:?}")]
    ProtocolError(Option<ParticipantIdentifier>),
    #[error("Some player sent more than one message of the same type: {0:?}")]
    DuplicateMessage(ParticipantIdentifier),
    #[error("Represents some code assumption that was checked at runtime but failed to be true")]
    InternalInvariantFailed,
    #[error("Unexpected state: {0:?} for protocol participant's status")]
    UnexpectedStatus(Status),
}

/// Errors that are caused by incorrect behavior by the calling application.
///
/// These are triggered when the calling application incorrectly
/// routes a message to the
/// [`process_single_message()`](crate::Participant::process_single_message())
/// method OR some other caller error.
#[derive(Clone, Eq, PartialEq, Error, Debug)]
#[allow(missing_docs)]
pub enum CallerError {
    #[error("Received a message with the wrong recipient ID")]
    WrongMessageRecipient,
    #[error("Received a message with the wrong session ID")]
    WrongSessionId,
    #[error("Received a message with the wrong protocol type for this participant (malicious behavior suspected)")]
    WrongProtocol,
    #[error("Received a message from a sender not included in the list of participants")]
    InvalidMessageSender,
    #[error("Received a message for a Protocol which has already terminated")]
    ProtocolAlreadyTerminated,
    #[error("The provided RNG failed to produce suitable values after a maximum number of attempts. Please check the RNG.")]
    RetryFailed,
    #[error("Tried to create an invalid `ParticipantConfig` (the protocol requires at least 2 uniquely identified parties)")]
    ParticipantConfigError,
    #[error("The provided input did not satisfy the requirements on the input type; see logs for details")]
    BadInput,
    #[error("Failed to deserialize bytes into the expected type")]
    DeserializationFailed,
    #[error("Failed to compute recovery ID for signature")]
    SignatureTrialRecoveryFailed,
}

macro_rules! serialize {
    ($x:expr) => {{
        bincode::serialize($x).or(Err(crate::errors::InternalError::Serialization))
    }};
}

macro_rules! deserialize {
    ($x:expr) => {{
        bincode::deserialize($x).or(Err(crate::errors::InternalError::Serialization))
    }};
}
