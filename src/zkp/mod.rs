// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2023 Bolt Labs, Inc.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a trait for zero-knowledge proofs.
//!
//! In more detail, this module provides a trait [`Proof`] for constructing a
//! (non-interactive) zero knowledge proof. The trait provides two methods,
//! [`Proof::prove`] and [`Proof::verify`]. The former builds a proof and the
//! latter verifies the proof was constructed correctly.

pub(crate) mod piaffg;
pub(crate) mod pienc;
pub(crate) mod pifac;
pub(crate) mod pilog;
pub(crate) mod pimod;
pub(crate) mod piprm;
pub(crate) mod pisch;

use crate::{curve_point::{CurvePoint, CurveTrait}, errors::Result};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};

/// A trait for constructing arbitrary system context.
///
/// This context can be turned into bytes and appended to a [`Transcript`].
pub(crate) trait ProofContext {
    fn as_bytes(&self) -> Result<Vec<u8>>;
}

#[cfg(test)]
impl ProofContext for () {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}

#[cfg(test)]
struct BadContext {}
#[cfg(test)]
impl ProofContext for BadContext {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok(vec![8u8])
    }
}

/// A trait for constructing zero knowledge proofs.
///
/// The associated type [`Proof::CommonInput`] denotes the data known to both
/// the prover and verifier, and the associated type [`Proof::ProverSecret`]
/// denotes the data known only to the prover.
pub(crate) trait Proof: Sized + Serialize + DeserializeOwned {
    type CommonInput<'a, C: CurveTrait> where C: 'a;
    type ProverSecret<'a>;

    /// Constructs a zero knowledge proof over [`Proof::ProverSecret`] and
    /// [`Proof::CommonInput`] using the provided [`Transcript`].
    fn prove<R: RngCore + CryptoRng>(
        input: Self::CommonInput<'_, CurvePoint>,
        secret: Self::ProverSecret<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self>;

    /// Verifies a zero knowledge proof using the provided
    /// [`Proof::CommonInput`] and [`Transcript`].
    fn verify(
        self,
        input: Self::CommonInput<'_, CurvePoint>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()>;
}
