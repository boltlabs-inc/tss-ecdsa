// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements the auxiliary information protocol defined in Figure
//! 6 of CGGMP21[^cite]. See
//! [`AuxInfoParticipant`](crate::auxinfo::participant::AuxInfoParticipant) for
//! more details.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/2021/060.pdf).

pub(crate) mod auxinfo_commit;
pub(crate) mod info;
pub mod participant;
pub(crate) mod proof;
