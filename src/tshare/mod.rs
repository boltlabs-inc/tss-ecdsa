//! Types and functions related to a threshold conversion sub-protocol.
//!
//! This protocol converts additive shares of an ECDSA key
//! into shamir shares. I.e. If party P_i holds s_i, then the output is a t of n
//! sharing of s_1 + ... s_n along with public commitments to the shares as
//! elliptic curve (EC) points. This protocol can be used to do threshold ECDSA
//! key generation by having each party use a random share as input.
//!
//! In the future, it can also be used to do key refresh, by having each
//! party non-interactively convert their input share using lagrangian
//! interpolation i.e. P_i holds (i,s_i) and converts input to (i,s_i*L_i(0))
//! where L_i is the lagrangian coefficient.
//!
//! Additionally, a party must check that other parties are sharing the correct
//! value via using their pre-existing public commitment.
//!
//! # High-level protocol description
//! The tshare protocol runs in four rounds:
//! - In the first round, each party generates a verifiable shamir secret
//!   sharing of a `share` value with threshold t for recovery. This share is
//!   specified as part of the input, and if it is not present a random value is
//!   chosen. The public parameters for Feldman's VSS are then commited to along
//!   with a schnorr pre-commitment.
//! - Once all commitment broadcasts have been received, the second round
//!   proceeds by each participant opening its commitment to all other
//!   participants. Each party also encrypts a different secret share from their
//!   VSS to every other party.
//! - In the third round, each participant checks that the commitment was
//!   correct, decrypts the messages with their received private shares and
//!   checks them against the public parameters of Feldman's VSS. The party then
//!   recovers their final private share by summing over their received shares
//!   and prove using schnorr that it matches the expected public share which
//!   can, again, be calculated from Feldman's VSS.
//! - In the final round, each party checks everyone else's schnorr proofs, with
//!   each public share being calculated from the feldman's parameters. At the
//!   end ouf the protocol, the party holds their final t of n share of the
//!   addition of the input shares, along with the public part of those shares
//!   held by other participants.
// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

mod commit;
mod input;
mod output;
mod participant;
mod share;

pub use input::Input;
pub use output::Output;
pub use participant::TshareParticipant;
pub use share::{CoeffPrivate, CoeffPublic};

#[cfg(test)]
pub(crate) use participant::tests;
