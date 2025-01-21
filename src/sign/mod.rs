// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements two signing protocols. [^cite]
//!
//! It includes both the interactive signing protocol (described in Figure 3)
//! and the non-interactive protocol (described in Figure 8).
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf).
//!
//! We expose our signature type in terms of the [`k256`] crate.

mod interactive_sign;
mod non_interactive_sign;

pub use interactive_sign::participant::{Input as InteractiveInput, InteractiveSignParticipant};
pub use non_interactive_sign::participant::{Input, SignParticipant};
