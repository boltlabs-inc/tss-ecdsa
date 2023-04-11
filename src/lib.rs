// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! # tss-ecdsa: A library for full-threshold ECDSA key generation and signing
//!
//! This work is based on the threshold ECDSA signature scheme described by
//! Canetti et al.[^cite], using `secp256k1`[^curve] as the elliptic curve. The
//! implementation is more limited than the cited protocol in several important
//! ways:
//!
//! 1. It is full-threshold: _all_ participants holding a share of the private
//! key must collaborate to produce a signature.
//!
//! 2. It does not implement key refresh. The paper ties this into the aux-info
//! protocol, but we removed the components that are only used to update the
//! participants' private key shares.
//!
//! 3. It does not implement identifiable abort. That is, the protocol will
//! abort if a party misbehaves, but we did not implement the procedures for
//! identifying which party was responsible.
//!
//!
//! ## Background
//! In a threshold signature scheme, a set of participants derive an asymmetric
//! key pair such that each of them holds only a share of the private signing
//! key, corresponding to a single public verification key. To produce a
//! signature, a group of size at least `t` of the signers can collaborate to
//! produce a valid signature for a message, while any subset of `t-1` signers
//! will be unable to do so (or to forge a valid signature).
//!
//! With the cited threshold ECDSA protocol, signatures are validated by a
//! regular (non-threshold) ECDSA verification function.  In fact, signatures
//! generated in this threshold manner are indistinguishable from signatures
//! generated using a normal ECDSA signing method.
//!
//!
//!
//! ## Architecture
//!
//! The main interfaces allow a [`Participant`] to process a message from
//! another participant, producing a set of outgoing messages and, if the
//! protocol completed, an output. The library handles
//! - out-of-order messaging
//! - protocol round execution
//!
//! # Requirements of the calling application
//! This library **does not** implement the complete protocol. There are several
//! security-critical steps that must be handled by the calling application. We
//! leave these undone intentionally, to allow increased flexibility in
//! deploying the library, but this does mean that it requires cryptographic
//! expertise to advise on security of the remaining components.
//!
//! 1. Networking. The protocol requires point-to-point channels between
//! individual participants, as well as a UC-secure, synchronous broadcast
//! mechanism. This library currently supports broadcast using the
//! echo-broadcast protocol described by Goldwasser and Lindell[^echo], so the
//! calling application only has to implement point-to-point channels. However,
//! this will likely change.
//!
//! 2. Secure persistent storage. The protocol is composed of four subprotocols,
//! each taking input and returning output. The calling application must persist
//! this output and provide it at subsequent protocol executions. Some of the
//! outputs are private values that should be stored securely. See
//! [`Participant`] for more details.
//!
//! # ⚠️ Security warning
//! The implementation in this crate has not been independently audited for
//! security! We have also not released a version that we have finished
//! internally auditing.
//!
//! At this time, we do not recommend use for security-critical applications.
//! Use at your own risk.
//!
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/2021/060.pdf).
//!
//! [^curve]: Secp256k1. [Bitcoin Wiki,
//!     2019](https://en.bitcoin.it/wiki/Secp256k1).
//!
//! [^echo]: Shafi Goldwasser and Yehuda Lindell. Secure Multi-Party Computation
//! without Agreement. [Journal of Cryptology,
//! 2005](https://link.springer.com/content/pdf/10.1007/s00145-005-0319-z.pdf).

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
mod local_storage;
mod message_queue;
mod messages;
mod paillier;
mod parameters;
mod participant;
mod presign;
mod protocol;
mod ring_pedersen;
mod utils;
mod zkp;
mod zkstar;

pub use auxinfo::{
    info::{AuxInfoPrivate, AuxInfoPublic},
    participant::AuxInfoParticipant,
};
pub use keygen::{
    keyshare::{KeySharePrivate, KeySharePublic},
    participant::KeygenParticipant,
};
pub use messages::Message;
pub use participant::ProtocolParticipant;
pub use presign::{
    participant::{Input as PresignInput, PresignParticipant},
    record::PresignRecord,
};
pub use protocol::{
    Identifier, Output, Participant, ParticipantConfig, ParticipantIdentifier, SignatureShare,
};
pub use utils::CurvePoint;

use crate::presign::*;

#[cfg(test)]
mod safe_primes_1024;
#[cfg(test)]
mod safe_primes_512;
