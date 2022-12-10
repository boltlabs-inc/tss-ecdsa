// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Generates setup parameters (N, s, t) used for other ZKPs. See
//! the paragraph before Section 2.3.1 of <https://eprint.iacr.org/2021/060.pdf>
//! for a description.

use crate::errors::*;
use libpaillier::unknown_order::BigNumber;

use super::piprm::{PiPrmInput, PiPrmProof, PiPrmSecret};
use crate::zkp::Proof;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ZkSetupParameters {
    pub(crate) N: BigNumber,
    pub(crate) s: BigNumber,
    pub(crate) t: BigNumber,
    piprm: PiPrmProof,
}

impl ZkSetupParameters {
    #[cfg(test)]
    pub(crate) fn gen<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let p = crate::utils::get_prime_from_pool_insecure(rng);
        let q = crate::utils::get_prime_from_pool_insecure(rng);
        let N = &p * &q;
        Self::gen_from_primes(rng, &N, &p, &q)
    }

    pub(crate) fn gen_from_primes<R: RngCore + CryptoRng>(
        rng: &mut R,
        N: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self> {
        let phi_n = (p - 1) * (q - 1);
        let tau = BigNumber::from_rng(N, rng);
        let lambda = BigNumber::from_rng(&phi_n, rng);
        let t = tau.modpow(&BigNumber::from(2), N);
        let s = t.modpow(&lambda, N);

        //let pimod = PiModProof::prove(rng, &PiModInput::new(N), &PiModSecret::new(p,
        // q))?;
        let piprm = PiPrmProof::prove(
            rng,
            &PiPrmInput::new(N, &s, &t),
            &PiPrmSecret::new(&lambda, &phi_n),
        )?;

        Ok(Self {
            N: N.clone(),
            s,
            t,
            //pimod,
            piprm,
        })
    }

    pub(crate) fn verify(&self) -> Result<()> {
        //self.pimod.verify(&PiModInput::new(&self.N))?;
        self.piprm
            .verify(&PiPrmInput::new(&self.N, &self.s, &self.t))?;
        Ok(())
    }
}
