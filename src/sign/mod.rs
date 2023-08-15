// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements two signing protocols defined in Canetti et
//! al[^cite].
//!
//! It includes both the interactive signing protocol (described in Figure 3)
//! and the non-interactive protocol (described in Figure 8).
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/2021/060.pdf).

mod interactive_sign;
mod non_interactive_sign;

use k256::Scalar;
use tracing::error;

use crate::errors::{InternalError, Result};

pub use interactive_sign::participant::{Input as InteractiveInput, InteractiveSignParticipant};
pub use non_interactive_sign::participant::{Input, SignParticipant};

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
