// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A list of error types which are produced during an execution of the protocol
use core::fmt::Debug;
use thiserror::Error;

use crate::paillier;

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
    #[error("Protocol error")]
    ProtocolError,
    #[error("Could not successfully generate proof")]
    CouldNotGenerateProof,
    #[error("Failed to verify proof")]
    FailedToVerifyProof,
    #[error("Represents some code assumption that was checked at runtime but failed to be true")]
    InternalInvariantFailed,
    #[error("Paillier error: `{0}`")]
    PaillierError(#[from] paillier::Error),
    #[error("Failed to convert BigNumber to k256::Scalar, as BigNumber was not in [0,p)")]
    CouldNotConvertToScalar,
    #[error("Could not invert a Scalar")]
    CouldNotInvertScalar,
    #[error("Reached the maximum allowed number of retries")]
    RetryFailed,
    #[error("This Participant was given a message intended for somebody else")]
    WrongMessageRecipient,
    #[error("Encountered a MessageType which was not expected in this context")]
    MisroutedMessage,
    #[error("Could not construct signature from provided scalars")]
    SignatureInstantiationError,
    #[error("Tried to produce a signature without including shares")]
    NoChainedShares,
    #[error("Storage does not contain the requested item")]
    StorageItemNotFound,
    #[error("The provided Broadcast Tag was not the expected tag for this context")]
    IncorrectBroadcastMessageTag,
    #[error("Encountered a Message sent directly, when it should have been broadcasted")]
    MessageMustBeBroadcasted,
    #[error("Broadcast has irrecoverably failed: `{0}`")]
    BroadcastFailure(String),
    #[error(
        "Tried to start a new protocol instance with an Identifier used in an existing instance"
    )]
    IdentifierInUse,
    #[error("Protocol has already terminated")]
    ProtocolAlreadyTerminated,
}

/// Errors that are caused by incorrect behavior by the calling application.
///
/// These are triggered when the calling application incorrectly
/// routes a message to the
/// [`process_single_message()`](crate::Participant::process_single_message())
/// method.
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
