// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements the signing protocol defined in Figure 8 of
//! the protocol by Canetti et al[^cite].
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/2021/060.pdf).

mod interactive_sign;
mod non_interactive_sign;

use k256::Scalar;
pub use non_interactive_sign::participant::Input;
use tracing::error;

use crate::errors::{InternalError, Result};

/// ECDSA signature on a message.
///
/// When generated by this library, the signature will be produced by the
/// threshold ECDSA algorithm by Canetti et al.
#[derive(Debug, PartialEq, Eq)]
pub struct Signature(k256::ecdsa::Signature);

impl Signature {
    pub(super) fn try_from_scalars(r: Scalar, s: Scalar) -> Result<Self> {
        Ok(Self(k256::ecdsa::Signature::from_scalars(r, s)
            .map_err(|e| {
                error!("Failed to generate `Signature` from `Scalar`s but they should be correctly formatted {e:?}");
                InternalError::InternalInvariantFailed
            })?
        ))
    }
}

impl AsRef<k256::ecdsa::Signature> for Signature {
    fn as_ref(&self) -> &k256::ecdsa::Signature {
        &self.0
    }
}
