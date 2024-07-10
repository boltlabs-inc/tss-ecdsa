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
//! # Usage
//! The [`Participant`] type is the main driver for protocol execution. A given
//! `Participant` is parameterized by the subprotocol that it runs:
//! [`keygen`](`keygen::KeygenParticipant`),
//! [`auxinfo`](auxinfo::AuxInfoParticipant),
//! [`presign`](presign::PresignParticipant),
//! [`sign`](sign::SignParticipant) or
//! [`interactive_sign`](sign::InteractiveSignParticipant).
//! As in the paper, interactive signing is equivalent to running presign and
//! sign back-to-back; you only have to generate one session ID and don't have
//! to handle secure storage of presign records, but don't get the benefit of
//! being able to "cache" message-independent records.
//!
//! A valid protocol run requires a lot of setup so we won't try to provide a
//! code example here; please see the examples directory. At a high level,
//! though, the user can run a protocol as follows:
//! 1. Create a new [`Participant`], parameterized by the
//!    [`ProtocolParticipant`] describing the protocol you want to run.
//! 2. Initialize the `Participant` by calling
//!    [`initialize_message()`](Participant::initialize_message()) and passing
//!    the result to
//!    [`process_single_message`](Participant::process_single_message()).
//! 3. Processing a message returns an optional output and a (possibly empty)
//!    set of messages. Send any messages to the other participants. If there's
//!    an output, the protocol is complete for this party.
//! 4. On receiving a message from another participant, call
//!    `process_single_message`. Repeat 3 and 4.
//!
//! Note that a `Participant` can receive messages before it has been
//! initialized. They will be stored and processed after initialization.
//!
//! # 🔒 Requirements of the calling application
//! This library **does not** implement the complete protocol. There are several
//! security-critical steps that must be handled by the calling application. We
//! leave these undone intentionally, to allow increased flexibility in
//! deploying the library, but this does mean that a successful, correct
//! deployment requires cryptographic expertise to advise on security of the
//! remaining components.
//!
//! These caller requirements are highlighted throughout the documentation with
//! the 🔒 symbol. At a high level, they include:
//!
//! 1. Networking. The protocol requires messages to be sent
//! between the [`Participant`]s, but the library does not implement _any_
//! networking; it simply produces messages to be sent out.
//! See [Networking section](#-networking) below for details, including
//! properties that channels must maintain and validation that the calling
//! application must do.
//!
//! 2. Secure persistent storage. The protocol is composed of four subprotocols,
//! each taking input and returning output. The calling application must persist
//! outputs, provide them as input for subsequent protocol executions, and
//! delete them at the end of their lifetimes. Some outputs are private values
//! that must be stored securely. See [`Participant`] for more details.
//!
//! 3. Identifier creation. To create a [`Participant`], the calling
//! application must specify a session [`Identifier`] and
//! [`ParticipantIdentifier`]s for each party. We do not specify a protocol for
//! creating these; depending on the trust assumptions of the deployment, the
//! caller can select an appropriate protocol that will ensure that all parties
//! agree on the set of identifiers. See [`Identifier`] and
//! [`ParticipantIdentifier`] for more details. They must satisfy several
//! properties:     
//!     1. All identifiers must be consistent across all
//! participants in a session.
//!     2. The session [`Identifier`] must be global and unique;
//! in particular, it must not be reused across multiple protocol
//! instances.
//!     3. The [`ParticipantIdentifier`]s must be unique within the session.
//! A [`ParticipantIdentifier`] assigned to a specific entity can be reused
//! across multiple session by that entity.
//! They should not be reused for different real-world entities; we don't make
//! any guarantees about system behavior when [`ParticipantIdentifier`]s are
//! reused in this way.
//!
//! ## 🔒 Networking
//!
//! The calling application is responsible for sending messages between
//! participants in the protocol.
//! All communication between [`Participant`]s must take place over a
//! channel that satisfies sender authentication and integrity.
//! In practice, this is typically instantiated using a public key
//! infrastructure (PKI) to associate signing keys to entities.
//! Briefly, each message is accompanied by a signature on that message, under
//! the signing key associated with the sending entity.
//! Since the library does not deal directly with communication channels, it
//! does not validate that messages are correctly associated with their sender.
//!
//! Instead, the calling application is responsible for maintaining a mapping
//! between the [`ParticipantIdentifier`] and the signing key associated with
//! each entity. [`Message`](messages::Message)s contain a `from:
//! ParticipantIdentifier` field which specifies the sender of a message. On
//! receiving a message and signature over a channel, the calling application
//! must check that the `from` field in the message matches the signing key used
//! to generate the signature. This ensures that the sender is not lying about
//! its identity.
//!
//! The protocol requires a UC-secure, synchronous, authenticated broadcast
//! channel for use by the [`Participant`]s. Currently, the library handles this
//! automatically by implementing the echo-broadcast protocol described by
//! Goldwasser and Lindell[^echo]. This is the approach the paper mentions,
//! but we emphasize that this reduces the security of the protocol to selective
//! abort[^abort] rather than the stronger notion of identifiable abort that is
//! achieved with an authenticated broadcast protocol.
//!
//!
//! # ⚠️ Security warning
//! The implementation in this crate has not been independently audited for
//! security! We have also not released a version that we have finished
//! internally auditing.
//!
//! At this time, we do not recommend use for security-critical applications.
//! Use at your own risk.
//!
//! # Useful features
//!
//! A [`Participant`] processes messages received from other [`Participant`]s
//! and generates [`Message`](messages::Message) for other  [`Participant`]s to
//! process. When the current sub-protocol finishes, output values are produced.
//!
//! Messages may arrive from the network before a [`Participant`] is ready to
//! process them. [`Participant`]s can be given messages at any time; when
//! messages are received early, they are stored in memory by the library and
//! retrieved and processed at the appropriate time.
//!
//! A sub-protocol session automatically progresses between rounds; the calling
//! application does not have to track where within a session the protocol
//! execution is at a given time.
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
//!
//! [^abort]: In a protocol that offers identifiable abort,
//! malicious participants may cause the protocol to abort but
//! honest participants are able to identify the malicious party (and take
//! recovery actions). In a protocol that offers selective abort, malicious
//! participants may cause _some_ honest participants to abort, but any
//! non-aborting honest participants have the correct output. This is weaker
//! because honest parties do not identify malicious parties and there is
//! inconsistency across honest parties on whether an abort happened or not.

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

pub mod auxinfo;
mod broadcast;
mod gmp_zeroize;
pub mod keygen;
pub mod keyrefresh;
mod local_storage;
mod message_queue;
pub mod messages;
mod paillier;
mod parameters;
mod participant;
pub mod presign;
mod protocol;
mod ring_pedersen;
pub mod sign;
mod utils;
mod zkp;
mod zkstar;

pub use gmp_zeroize::enable_zeroize;
pub use participant::ProtocolParticipant;
pub use protocol::{
    participant_config::ParticipantConfig, Identifier, Participant, ParticipantIdentifier,
};

use crate::presign::*;

#[cfg(test)]
mod safe_primes_1024;
#[cfg(test)]
mod safe_primes_512;
