// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

pub(crate) mod piaffg;
pub(crate) mod pienc;
pub(crate) mod pifac;
pub(crate) mod pilog;
pub(crate) mod pimod;
pub(crate) mod piprm;
pub(crate) mod pisch;

use crate::errors::Result;
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
pub(crate) trait Proof: Sized + Serialize + DeserializeOwned {
    type CommonInput;
    type ProverSecret;

    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self>;

    fn verify(&self, input: &Self::CommonInput) -> Result<()>;
}
