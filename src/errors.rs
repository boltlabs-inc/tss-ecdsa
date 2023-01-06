// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A list of error types which are produced during an execution of the protocol
use core::fmt::Debug;
use thiserror::Error;

use crate::paillier::PaillierError;

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
    #[error("One or more of the integer inputs to the Chinese remainder theorem were outside the expected range")]
    InvalidIntegers,
    #[error(
        "Could not find uniqueness for fourth roots combination in Paillier-Blum modulus proof"
    )]
    NonUniqueFourthRootsCombination,
    #[error("Could not invert a BigNumber")]
    CouldNotInvertBigNumber,
    #[error("`{0}`")]
    BailError(String),
    #[error("Represents some code assumption that was checked at runtime but failed to be true")]
    InternalInvariantFailed,
    #[error("Paillier error: `{0}`")]
    PaillierError(PaillierError),
    #[error("Failed to convert BigNumber to k256::Scalar, as BigNumber was not in [0,p)")]
    CouldNotConvertToScalar,
    #[error("Could not invert a Scalar")]
    CouldNotInvertScalar,
    #[error("Reached the maximum allowed number of retries")]
    RetryFailed,
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

macro_rules! bail {
    ($msg:literal $(,)?) => {
        Err(bail_context!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        Err(bail_context!($fmt, $($arg)*))
    };
}

macro_rules! bail_context {
    ($msg:literal $(,)?) => {
        crate::errors::InternalError::BailError(String::from($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        crate::errors::InternalError::BailError(format!($fmt, $($arg)*))
    };
}
