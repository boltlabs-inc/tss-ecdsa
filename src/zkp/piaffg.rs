// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 15 of <https://eprint.iacr.org/2021/060.pdf>
//!
//! Proves that the prover knows an x and y where X = g^x and y is the
//! plaintext of a Paillier ciphertext

use super::Proof;
use crate::{
    errors::*,
    parameters::{ELL, ELL_PRIME, EPSILON},
    utils::{
        self, k256_order, modpow, plusminus_bn_random_from_transcript, random_bn_in_range,
        random_bn_in_z_star, random_bn_plusminus,
    },
    zkp::setup::ZkSetupParameters,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use utils::CurvePoint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiAffgProof {
    alpha: BigNumber,
    beta: BigNumber,
    S: BigNumber,
    T: BigNumber,
    A: BigNumber,
    B_x: CurvePoint,
    B_y: BigNumber,
    E: BigNumber,
    F: BigNumber,
    e: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    z3: BigNumber,
    z4: BigNumber,
    w: BigNumber,
    w_y: BigNumber,
}

#[derive(Serialize)]
pub(crate) struct PiAffgInput {
    setup_params: ZkSetupParameters,
    g: CurvePoint,
    N0: BigNumber,
    N1: BigNumber,
    C: BigNumber,
    D: BigNumber,
    Y: BigNumber,
    X: CurvePoint,
}

impl PiAffgInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        setup_params: &ZkSetupParameters,
        g: &CurvePoint,
        N0: &BigNumber,
        N1: &BigNumber,
        C: &BigNumber,
        D: &BigNumber,
        Y: &BigNumber,
        X: &CurvePoint,
    ) -> Self {
        Self {
            setup_params: setup_params.clone(),
            g: *g,
            N0: N0.clone(),
            N1: N1.clone(),
            C: C.clone(),
            D: D.clone(),
            Y: Y.clone(),
            X: *X,
        }
    }
}

pub(crate) struct PiAffgSecret {
    x: BigNumber,
    y: BigNumber,
    rho: BigNumber,
    rho_y: BigNumber,
}

impl PiAffgSecret {
    pub(crate) fn new(x: &BigNumber, y: &BigNumber, rho: &BigNumber, rho_y: &BigNumber) -> Self {
        Self {
            x: x.clone(),
            y: y.clone(),
            rho: rho.clone(),
            rho_y: rho_y.clone(),
        }
    }
}

// Common input is: g, N0, N1, C, D, Y, X
// Prover secrets are: (x, y, rho, rho_y)
//
// (Note that we use ELL = ELL' from the paper)
impl Proof for PiAffgProof {
    type CommonInput = PiAffgInput;
    type ProverSecret = PiAffgSecret;

    // N0: modulus, K: Paillier ciphertext
    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    #[allow(clippy::many_single_char_names)]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // Sample alpha from 2^{ELL + EPSILON}
        let alpha = random_bn_in_range(rng, ELL + EPSILON);
        // Sample beta from 2^{ELL_PRIME + EPSILON}.
        let beta = random_bn_in_range(rng, ELL_PRIME + EPSILON);

        let r = random_bn_in_z_star(rng, &input.N0);
        let r_y = random_bn_in_z_star(rng, &input.N1);

        // range_ell_eps = 2^{ELL + EPSILON} * N_hat
        let range_ell_eps = (BigNumber::one() << (ELL + EPSILON)) * &input.setup_params.N;
        let gamma = random_bn_plusminus(rng, &range_ell_eps);
        let delta = random_bn_plusminus(rng, &range_ell_eps);

        // range_ell = 2^ELL * N_hat
        let range_ell = (BigNumber::one() << ELL) * &input.setup_params.N;
        let m = random_bn_plusminus(rng, &range_ell);
        let mu = random_bn_plusminus(rng, &range_ell);

        let N0_squared = &input.N0 * &input.N0;
        let N1_squared = &input.N1 * &input.N1;

        let A = {
            let a = modpow(&input.C, &alpha, &N0_squared);
            let b = {
                let c = modpow(&(BigNumber::one() + &input.N0), &beta, &N0_squared);
                let d = modpow(&r, &input.N0, &N0_squared);
                c.modmul(&d, &N0_squared)
            };
            a.modmul(&b, &N0_squared)
        };
        let B_x = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha).unwrap());
        let B_y = {
            let a = modpow(&(BigNumber::one() + &input.N1), &beta, &N1_squared);
            let b = modpow(&r_y, &input.N1, &N1_squared);
            a.modmul(&b, &N1_squared)
        };
        let E = {
            let a = modpow(&input.setup_params.s, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &gamma, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let S = {
            let a = modpow(&input.setup_params.s, &secret.x, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &m, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let F = {
            let a = modpow(&input.setup_params.s, &beta, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &delta, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let T = {
            let a = modpow(&input.setup_params.s, &secret.y, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &mu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };

        let mut transcript = Transcript::new(b"PiAffgProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, T, A, B_x, B_y, E, F)",
            &[
                S.to_bytes(),
                T.to_bytes(),
                A.to_bytes(),
                bincode::serialize(&B_x).unwrap(),
                B_y.to_bytes(),
                E.to_bytes(),
                F.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &k256_order());

        let z1 = &alpha + &e * &secret.x;
        let z2 = &beta + &e * &secret.y;
        let z3 = gamma + &e * m;
        let z4 = delta + &e * mu;
        let w = r.modmul(&modpow(&secret.rho, &e, &input.N0), &input.N0);
        let w_y = r_y.modmul(&modpow(&secret.rho_y, &e, &input.N1), &input.N1);

        let proof = Self {
            alpha,
            beta,
            S,
            T,
            A,
            B_x,
            B_y,
            E,
            F,
            e,
            z1,
            z2,
            z3,
            z4,
            w,
            w_y,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // First, do Fiat-Shamir consistency check

        let mut transcript = Transcript::new(b"PiAffgProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, T, A, B_x, B_y, E, F)",
            &[
                self.S.to_bytes(),
                self.T.to_bytes(),
                self.A.to_bytes(),
                bincode::serialize(&self.B_x).unwrap(),
                self.B_y.to_bytes(),
                self.E.to_bytes(),
                self.F.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &k256_order());

        if e != self.e {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        let N0_squared = &input.N0 * &input.N0;
        let N1_squared = &input.N1 * &input.N1;

        // Do equality checks

        let eq_check_1 = {
            let a = modpow(&input.C, &self.z1, &N0_squared);
            let b = modpow(&(BigNumber::one() + &input.N0), &self.z2, &N0_squared);
            let c = modpow(&self.w, &input.N0, &N0_squared);
            let lhs = a.modmul(&b, &N0_squared).modmul(&c, &N0_squared);
            let rhs = self
                .A
                .modmul(&modpow(&input.D, &self.e, &N0_squared), &N0_squared);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z1).unwrap());
            let rhs = CurvePoint(self.B_x.0 + input.X.0 * utils::bn_to_scalar(&self.e).unwrap());
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let a = modpow(&(BigNumber::one() + &input.N1), &self.z2, &N1_squared);
            let b = modpow(&self.w_y, &input.N1, &N1_squared);
            let lhs = a.modmul(&b, &N1_squared);
            let rhs = self
                .B_y
                .modmul(&modpow(&input.Y, &self.e, &N1_squared), &N1_squared);
            lhs == rhs
        };
        if !eq_check_3 {
            return verify_err!("eq_check_3 failed");
        }

        let eq_check_4 = {
            let a = modpow(&input.setup_params.s, &self.z1, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z3, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.E.modmul(
                &modpow(&self.S, &self.e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_4 {
            return verify_err!("eq_check_4 failed");
        }

        let eq_check_5 = {
            let a = modpow(&input.setup_params.s, &self.z2, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z4, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.F.modmul(
                &modpow(&self.T, &self.e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_5 {
            return verify_err!("eq_check_5 failed");
        }

        // Do range check

        let ell_bound = BigNumber::one() << (ELL + EPSILON);
        let ell_prime_bound = BigNumber::one() << (ELL_PRIME + EPSILON);
        if self.z1 < -ell_bound.clone() || self.z1 > ell_bound {
            return verify_err!("self.z1 > ell_bound check failed");
        }
        if self.z2 < -ell_prime_bound.clone() || self.z2 > ell_prime_bound {
            return verify_err!("self.z2 > ell_prime_bound check failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{paillier::PaillierEncryptionKey, utils::random_bn_in_range_min};
    use libpaillier::*;
    use rand::rngs::OsRng;

    fn random_paillier_affg_proof(x: &BigNumber, y: &BigNumber) -> Result<()> {
        let mut rng = OsRng;

        let p0 = crate::utils::get_random_safe_prime_512();
        let q0 = loop {
            let q0 = crate::utils::get_random_safe_prime_512();
            if p0 != q0 {
                break q0;
            }
        };

        let N0 = &p0 * &q0;

        let p1 = crate::utils::get_random_safe_prime_512();
        let q1 = loop {
            let q1 = crate::utils::get_random_safe_prime_512();
            if p1 != q1 {
                break q1;
            }
        };
        let N1 = &p1 * &q1;

        let sk0 = DecryptionKey::with_safe_primes_unchecked(&p0, &q0).unwrap();
        let pk0 = PaillierEncryptionKey(EncryptionKey::from(&sk0));

        let sk1 = DecryptionKey::with_safe_primes_unchecked(&p1, &q1).unwrap();
        let pk1 = PaillierEncryptionKey(EncryptionKey::from(&sk1));

        let g = k256::ProjectivePoint::GENERATOR;

        let X = CurvePoint(g * utils::bn_to_scalar(x).unwrap());
        let (Y, rho_y) = pk1.encrypt(y);

        let N0_squared = &N0 * &N0;
        let C = crate::utils::random_positive_bn(&mut rng, &N0_squared);

        // Compute D = C^x * (1 + N0)^y rho^N0 (mod N0^2)
        let (D, rho) = {
            let (D_intermediate, rho) = pk0.encrypt(y);
            let D = modpow(&C, x, &N0_squared).modmul(&D_intermediate, &N0_squared);
            (D, rho)
        };

        let setup_params = ZkSetupParameters::gen(&mut rng)?;

        let input = PiAffgInput::new(&setup_params, &CurvePoint(g), &N0, &N1, &C, &D, &Y, &X);
        let proof = PiAffgProof::prove(&mut rng, &input, &PiAffgSecret::new(x, y, &rho, &rho_y))?;

        proof.verify(&input)
    }

    #[test]
    fn test_paillier_affg_proof() -> Result<()> {
        let mut rng = OsRng;

        let x_small = random_bn_in_range(&mut rng, ELL);
        let y_small = random_bn_in_range(&mut rng, ELL_PRIME);
        let x_large = random_bn_in_range_min(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;
        let y_large =
            random_bn_in_range_min(&mut rng, ELL_PRIME + EPSILON + 1, ELL_PRIME + EPSILON)?;

        // Sampling x in 2^ELL and y in 2^{ELL_PRIME} should always succeed
        random_paillier_affg_proof(&x_small, &y_small)?;

        // All other combinations should fail
        assert!(random_paillier_affg_proof(&x_small, &y_large).is_err());
        assert!(random_paillier_affg_proof(&x_large, &y_small).is_err());
        assert!(random_paillier_affg_proof(&x_large, &y_large).is_err());

        Ok(())
    }
}
