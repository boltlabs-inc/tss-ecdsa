//! Types and functions related to key generation sub-protocol.[^cite]
//!
//! Produces an ECDSA public key where the private key shares are
//! additively split among n parties.
//!
//! # High-level protocol description
//! The key generation protocol runs in four rounds:
//! - In the first round, each participant broadcasts a commitment to (1) its
//!   public key share and (2) a "precommitment" to a Schnorr proof.
//! - Once all commitment broadcasts have been received, the second round
//!   proceeds by each participant opening its commitment to all other
//!   participants.
//! - In the third round, each participant (1) checks the validity of all the
//!   commitments, and (2) produces a Schnorr proof that it knows the private
//!   key corresponding to its public keyshare, and sends this proof to all
//!   other participants.
//! - Finally, in the last round each participant checks the validity of all
//!   other participants' Schnorr proofs. If that succeeds, each participant
//!   outputs all the public key shares alongside its own private key share and
//!   a global random value, produced with contributory randomness from all
//!   parties.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf). Figure 5.
// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

mod keygen_commit;
mod keyshare;
pub mod output;
mod participant;

pub use keyshare::{KeySharePrivate, KeySharePublic};
pub use output::Output;
pub use participant::KeygenParticipant;
