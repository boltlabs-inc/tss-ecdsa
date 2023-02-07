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
    #[error("Serialization Error")]
    Serialization,
    #[error("Could not successfully generate proof")]
    CouldNotGenerateProof,
    #[error("Failed to verify proof: `{0}`")]
    FailedToVerifyProof(String),
    #[error("Could not find square roots modulo n")]
    NoSquareRoots,
    #[error("Elements are not coprime")]
    NotCoprime,
    #[error("Elements of the multiplicative group ZK*_N cannot be larger than the RSA modulus")]
    LargerThanModulus,
    #[error("Elements of the multiplicative group ZK*_N cannot be negative")]
    NegativeElement,
    #[error("Elements of the multiplicative group  ZK*_N cannot be zero")]
    IsZero,
    #[error("One or more of the integer inputs to the Chinese remainder theorem were outside the expected range")]
    InvalidIntegers,
    #[error(
        "Could not find uniqueness for fourth roots combination in Paillier-Blum modulus proof"
    )]
    NonUniqueFourthRootsCombination,
    #[error("Could not invert a BigNumber")]
    CouldNotInvertBigNumber,
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
    #[error("Function call contained invalid arguments: `{0}`")]
    InvalidArgument(String),
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

macro_rules! verify_err {
    ($x:expr) => {{
        Err(crate::errors::InternalError::FailedToVerifyProof(
            String::from($x),
        ))
    }};
}

macro_rules! arg_err {
    ($x:expr) => {{
        Err(crate::errors::InternalError::InvalidArgument(String::from(
            $x,
        )))
    }};
}
