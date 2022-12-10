// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implementation of the CMP threshold ECDSA signature protocol
//!
//! In a threshold signature scheme, a subset t of n signers, each
//! of whom hold a share of a private signing key, can
//! communicate to produce a valid signature for a message, while
//! any subset of t-1 signers will be unable to forge signatures.
//!
//! A threshold ECDSA signature scheme is specific to the ECDSA
//! signature scheme, where the signatures can be validated by a
//! regular (non-threshold) ECDSA verification function. In fact,
//! signatures generated in this threshold manner are indistinguishable
//! from signatures generated using a normal ECDSA signing method.
//!
//! In this implementation, we instantiate the threshold ECDSA
//! signature scheme described in [CGGMP'21](https://eprint.iacr.org/2021/060),
//! using [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) as the elliptic curve.
//!
//! Note that this library only provides the low-level interfaces for executing
//! each of the rounds of the protocol, notably without handling communication
//! and parallel execution. The main interfaces allow for a [Participant] to
//! process a message from another participant, producing a set of outgoing
//! messages that in turn must be delivered to other participants.
//!
//! For an example of how to actually integrate this library into a higher-level
//! application that handles the communication between participants in parallel,
//! take a look at the provided [network example](./examples/network/README.md).

#![allow(non_snake_case)] // FIXME: To be removed in the future
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]
#![cfg_attr(feature = "flame_it", feature(proc_macro_hygiene))]
#[cfg(feature = "flame_it")]
extern crate flame;
#[cfg(feature = "flame_it")]
#[macro_use]
extern crate flamer;

#[macro_use]
pub mod errors;

mod auxinfo;
mod broadcast;
mod keygen;
mod message_queue;
mod messages;
mod paillier;
mod parameters;
mod participant;
mod presign;
mod protocol;
mod safe_primes_512;
mod storage;
mod utils;
mod zkp;

pub use messages::Message;
pub use protocol::{
    Identifier, Participant, ParticipantConfig, ParticipantIdentifier, SignatureShare,
};
pub use utils::CurvePoint;

use crate::presign::*;
