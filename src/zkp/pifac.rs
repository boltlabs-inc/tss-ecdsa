// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 28 of <https://eprint.iacr.org/2021/060.pdf>

use super::Proof;
use crate::{
    errors::*,
    parameters::{ELL, EPSILON},
    utils::{k256_order, modpow, plusminus_bn_random_from_transcript, random_bn_plusminus},
    zkp::setup::ZkSetupParameters,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use num_bigint::{BigInt, Sign};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct PiFacProof {
    P: BigNumber,
    Q: BigNumber,
    A: BigNumber,
    B: BigNumber,
    T: BigNumber,
    sigma: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    w1: BigNumber,
    w2: BigNumber,
    v: BigNumber,
}

#[derive(Serialize)]
pub(crate) struct PiFacInput {
    setup_params: ZkSetupParameters,
    N0: BigNumber,
}

impl PiFacInput {
    pub(crate) fn new(setup_params: &ZkSetupParameters, N0: &BigNumber) -> Self {
        Self {
            setup_params: setup_params.clone(),
            N0: N0.clone(),
        }
    }
}

pub(crate) struct PiFacSecret {
    p: BigNumber,
    q: BigNumber,
}

impl PiFacSecret {
    pub(crate) fn new(p: &BigNumber, q: &BigNumber) -> Self {
        Self {
            p: p.clone(),
            q: q.clone(),
        }
    }
}

impl Proof for PiFacProof {
    type CommonInput = PiFacInput;
    type ProverSecret = PiFacSecret;

    #[cfg_attr(feature = "flame_it", flame("PiFacProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // N_hat = input.setup_params.N
        let sqrt_N0 = sqrt(&input.N0);
        // 2^{ELL}
        let two_ell = BigNumber::one() << (ELL);
        // 2^{ELL + EPSILON}
        let two_ell_eps = BigNumber::one() << (ELL + EPSILON);
        // 2^{ELL + EPSILON} * sqrt(N_0)
        let ab_range = &sqrt_N0 * &two_ell_eps;
        // 2^{ELL} * N_hat
        let uv_range = &two_ell * &input.setup_params.N;
        // 2^{ELL} * N_0 * N_hat
        let s_range = &two_ell * &input.N0 * &input.setup_params.N;
        // 2^{ELL + EPSILON} * N_0 * N_hat
        let r_range = &two_ell_eps * &input.N0 * &input.setup_params.N;
        // 2^{ELL + EPSILON} * N_hat
        let xy_range = &two_ell_eps * &input.setup_params.N;

        let alpha = random_bn_plusminus(rng, &ab_range);
        let beta = random_bn_plusminus(rng, &ab_range);
        let mu = random_bn_plusminus(rng, &uv_range);
        let nu = random_bn_plusminus(rng, &uv_range);
        let sigma = random_bn_plusminus(rng, &s_range);
        let r = random_bn_plusminus(rng, &r_range);
        let x = random_bn_plusminus(rng, &xy_range);
        let y = random_bn_plusminus(rng, &xy_range);

        let P = {
            let a = modpow(&input.setup_params.s, &secret.p, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &mu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let Q = {
            let a = modpow(&input.setup_params.s, &secret.q, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &nu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let A = {
            let a = modpow(&input.setup_params.s, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &x, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let B = {
            let a = modpow(&input.setup_params.s, &beta, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &y, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let T = {
            let a = modpow(&Q, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &r, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };

        let mut transcript = Transcript::new(b"PiFacProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(P, Q, A, B, T, sigma)",
            &[
                P.to_bytes(),
                Q.to_bytes(),
                A.to_bytes(),
                B.to_bytes(),
                T.to_bytes(),
                sigma.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &k256_order());

        let sigma_hat = &sigma - &nu * &secret.p;
        let z1 = &alpha + &e * &secret.p;
        let z2 = &beta + &e * &secret.q;
        let w1 = &x + &e * &mu;
        let w2 = &y + &e * &nu;
        let v = &r + &e * &sigma_hat;

        let proof = Self {
            P,
            Q,
            A,
            B,
            T,
            sigma,
            z1,
            z2,
            w1,
            w2,
            v,
        };
        Ok(proof)
    }

    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        let mut transcript = Transcript::new(b"PiFacProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(P, Q, A, B, T, sigma)",
            &[
                self.P.to_bytes(),
                self.Q.to_bytes(),
                self.A.to_bytes(),
                self.B.to_bytes(),
                self.T.to_bytes(),
                self.sigma.to_bytes(),
            ]
            .concat(),
        );
        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &k256_order());

        let eq_check_1 = {
            let a1 = modpow(&input.setup_params.s, &self.z1, &input.setup_params.N);
            let b1 = modpow(&input.setup_params.t, &self.w1, &input.setup_params.N);
            let lhs = a1.modmul(&b1, &input.setup_params.N);
            let b2 = modpow(&self.P, &e, &input.setup_params.N);
            let rhs = self.A.modmul(&b2, &input.setup_params.N);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let a1 = modpow(&input.setup_params.s, &self.z2, &input.setup_params.N);
            let b1 = modpow(&input.setup_params.t, &self.w2, &input.setup_params.N);
            let lhs = a1.modmul(&b1, &input.setup_params.N);
            let b2 = modpow(&self.Q, &e, &input.setup_params.N);
            let rhs = self.B.modmul(&b2, &input.setup_params.N);
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let a0 = modpow(&input.setup_params.s, &input.N0, &input.setup_params.N);
            let b0 = modpow(&input.setup_params.t, &self.sigma, &input.setup_params.N);
            let R = a0.modmul(&b0, &input.setup_params.N);
            let a1 = modpow(&self.Q, &self.z1, &input.setup_params.N);
            let b1 = modpow(&input.setup_params.t, &self.v, &input.setup_params.N);
            let lhs = a1.modmul(&b1, &input.setup_params.N);
            let b2 = modpow(&R, &e, &input.setup_params.N);
            let rhs = self.T.modmul(&b2, &input.setup_params.N);
            lhs == rhs
        };
        if !eq_check_3 {
            return verify_err!("eq_check_3 failed");
        }

        let sqrt_N0 = sqrt(&input.N0);
        // 2^{ELL + EPSILON}
        let two_ell_eps = BigNumber::one() << (ELL + EPSILON);
        // 2^{ELL + EPSILON} * sqrt(N_0)
        let z_bound = &sqrt_N0 * &two_ell_eps;
        if self.z1 < -z_bound.clone() || self.z1 > z_bound {
            return verify_err!("self.z1 > z_bound check failed");
        }
        if self.z2 < -z_bound.clone() || self.z2 > z_bound {
            return verify_err!("self.z2 > z_bound check failed");
        }

        Ok(())
    }
}

/// Find the square root of a positive BigNumber, rounding down
fn sqrt(num: &BigNumber) -> BigNumber {
    // convert to a struct with a square root function first
    let num_bigint: BigInt = BigInt::from_bytes_be(Sign::Plus, &num.to_bytes());
    let sqrt = num_bigint.sqrt();
    let sqrt_bignum: BigNumber = BigNumber::from_slice(&sqrt.to_bytes_be().1);
    sqrt_bignum
}

impl PiFacProof {
    pub(crate) fn prove_with_transcript<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &PiFacInput,
        secret: &PiFacSecret,
        transcript: &mut Transcript,
    ) -> Result<Self> {
        // N_hat = input.setup_params.N
        let sqrt_N0 = sqrt(&input.N0);
        // 2^{ELL}
        let two_ell = BigNumber::one() << (ELL);
        // 2^{ELL + EPSILON}
        let two_ell_eps = BigNumber::one() << (ELL + EPSILON);
        // 2^{ELL + EPSILON} * sqrt(N_0)
        let ab_range = &sqrt_N0 * &two_ell_eps;
        // 2^{ELL} * N_hat
        let uv_range = &two_ell * &input.setup_params.N;
        // 2^{ELL} * N_0 * N_hat
        let s_range = &two_ell * &input.N0 * &input.setup_params.N;
        // 2^{ELL + EPSILON} * N_0 * N_hat
        let r_range = &two_ell_eps * &input.N0 * &input.setup_params.N;
        // 2^{ELL + EPSILON} * N_hat
        let xy_range = &two_ell_eps * &input.setup_params.N;

        let alpha = random_bn_plusminus(rng, &ab_range);
        let beta = random_bn_plusminus(rng, &ab_range);
        let mu = random_bn_plusminus(rng, &uv_range);
        let nu = random_bn_plusminus(rng, &uv_range);
        let sigma = random_bn_plusminus(rng, &s_range);
        let r = random_bn_plusminus(rng, &r_range);
        let x = random_bn_plusminus(rng, &xy_range);
        let y = random_bn_plusminus(rng, &xy_range);

        let P = {
            let a = modpow(&input.setup_params.s, &secret.p, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &mu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let Q = {
            let a = modpow(&input.setup_params.s, &secret.q, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &nu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let A = {
            let a = modpow(&input.setup_params.s, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &x, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let B = {
            let a = modpow(&input.setup_params.s, &beta, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &y, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let T = {
            let a = modpow(&Q, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &r, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };

        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(P, Q, A, B, T, sigma)",
            &[
                P.to_bytes(),
                Q.to_bytes(),
                A.to_bytes(),
                B.to_bytes(),
                T.to_bytes(),
                sigma.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(transcript, &k256_order());

        let sigma_hat = &sigma - &nu * &secret.p;
        let z1 = &alpha + &e * &secret.p;
        let z2 = &beta + &e * &secret.q;
        let w1 = &x + &e * &mu;
        let w2 = &y + &e * &nu;
        let v = &r + &e * &sigma_hat;

        let proof = Self {
            P,
            Q,
            A,
            B,
            T,
            sigma,
            z1,
            z2,
            w1,
            w2,
            v,
        };
        Ok(proof)
    }

    pub(crate) fn verify_with_transcript(
        &self,
        input: &PiFacInput,
        transcript: &mut Transcript,
    ) -> Result<()> {
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(P, Q, A, B, T, sigma)",
            &[
                self.P.to_bytes(),
                self.Q.to_bytes(),
                self.A.to_bytes(),
                self.B.to_bytes(),
                self.T.to_bytes(),
                self.sigma.to_bytes(),
            ]
            .concat(),
        );
        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(transcript, &k256_order());

        let eq_check_1 = {
            let a1 = modpow(&input.setup_params.s, &self.z1, &input.setup_params.N);
            let b1 = modpow(&input.setup_params.t, &self.w1, &input.setup_params.N);
            let lhs = a1.modmul(&b1, &input.setup_params.N);
            let b2 = modpow(&self.P, &e, &input.setup_params.N);
            let rhs = self.A.modmul(&b2, &input.setup_params.N);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let a1 = modpow(&input.setup_params.s, &self.z2, &input.setup_params.N);
            let b1 = modpow(&input.setup_params.t, &self.w2, &input.setup_params.N);
            let lhs = a1.modmul(&b1, &input.setup_params.N);
            let b2 = modpow(&self.Q, &e, &input.setup_params.N);
            let rhs = self.B.modmul(&b2, &input.setup_params.N);
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let a0 = modpow(&input.setup_params.s, &input.N0, &input.setup_params.N);
            let b0 = modpow(&input.setup_params.t, &self.sigma, &input.setup_params.N);
            let R = a0.modmul(&b0, &input.setup_params.N);
            let a1 = modpow(&self.Q, &self.z1, &input.setup_params.N);
            let b1 = modpow(&input.setup_params.t, &self.v, &input.setup_params.N);
            let lhs = a1.modmul(&b1, &input.setup_params.N);
            let b2 = modpow(&R, &e, &input.setup_params.N);
            let rhs = self.T.modmul(&b2, &input.setup_params.N);
            lhs == rhs
        };
        if !eq_check_3 {
            return verify_err!("eq_check_3 failed");
        }

        let sqrt_N0 = sqrt(&input.N0);
        // 2^{ELL + EPSILON}
        let two_ell_eps = BigNumber::one() << (ELL + EPSILON);
        // 2^{ELL + EPSILON} * sqrt(N_0)
        let z_bound = &sqrt_N0 * &two_ell_eps;
        if self.z1 < -z_bound.clone() || self.z1 > z_bound {
            return verify_err!("self.z1 > z_bound check failed");
        }
        if self.z2 < -z_bound.clone() || self.z2 > z_bound {
            return verify_err!("self.z2 > z_bound check failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_no_small_factors_proof() -> Result<(PiFacInput, PiFacProof)> {
        let mut rng = OsRng;

        let p0 = crate::utils::get_random_safe_prime_512();
        let q0 = loop {
            let q0 = crate::utils::get_random_safe_prime_512();
            if p0 != q0 {
                break q0;
            }
        };

        let N0 = &p0 * &q0;
        let setup_params = ZkSetupParameters::gen(&mut rng)?;

        let input = PiFacInput::new(&setup_params, &N0);
        let proof = PiFacProof::prove(&mut rng, &input, &PiFacSecret::new(&p0, &q0))?;

        Ok((input, proof))
    }

    #[test]
    fn test_no_small_factors_proof() -> Result<()> {
        let (input, proof) = random_no_small_factors_proof()?;
        proof.verify(&input)?;
        Ok(())
    }

    #[test]
    fn test_no_small_factors_proof_negative_cases() -> Result<()> {
        let mut rng = OsRng;
        let (input, proof) = random_no_small_factors_proof()?;

        let incorrect_N = PiFacInput::new(
            &input.setup_params,
            &crate::utils::get_random_safe_prime_512(),
        );
        assert!(proof.verify(&incorrect_N).is_err());

        let incorrect_startup_params =
            PiFacInput::new(&ZkSetupParameters::gen(&mut rng)?, &input.N0);
        assert!(proof.verify(&incorrect_startup_params).is_err());

        let not_p0 = crate::utils::get_random_safe_prime_512();
        let not_q0 = loop {
            let not_q0 = crate::utils::get_random_safe_prime_512();
            if not_p0 != not_q0 {
                break not_q0;
            }
        };
        let incorrect_factors =
            PiFacProof::prove(&mut rng, &input, &PiFacSecret::new(&not_p0, &not_q0))?;
        assert!(incorrect_factors.verify(&input).is_err());

        let small_p = BigNumber::from(7u64);
        let small_q = BigNumber::from(11u64);
        let setup_params = ZkSetupParameters::gen(&mut rng)?;
        let small_input = PiFacInput::new(&setup_params, &(&small_p * &small_q));
        let small_proof =
            PiFacProof::prove(&mut rng, &input, &PiFacSecret::new(&small_p, &small_q))?;
        assert!(small_proof.verify(&small_input).is_err());

        let regular_sized_q = crate::utils::get_random_safe_prime_512();
        let mixed_input = PiFacInput::new(&setup_params, &(&small_p * &regular_sized_q));
        let mixed_proof = PiFacProof::prove(
            &mut rng,
            &input,
            &PiFacSecret::new(&small_p, &regular_sized_q),
        )?;
        assert!(mixed_proof.verify(&mixed_input).is_err());

        let small_fac_p = &not_p0 * &BigNumber::from(2u64);
        let small_fac_input = PiFacInput::new(&setup_params, &(&small_fac_p * &regular_sized_q));
        let small_fac_proof = PiFacProof::prove(
            &mut rng,
            &input,
            &PiFacSecret::new(&small_fac_p, &regular_sized_q),
        )?;
        assert!(small_fac_proof.verify(&small_fac_input).is_err());

        Ok(())
    }

    #[test]
    // Make sure the bytes representations for BigNum and BigInt
    // didn't change in a way that would mess up the sqrt funtion
    fn test_bignum_bigint_byte_representation() -> Result<()> {
        let p0 = crate::utils::get_random_safe_prime_512();
        let q0 = loop {
            let q0 = crate::utils::get_random_safe_prime_512();
            if p0 != q0 {
                break q0;
            }
        };

        let num = &p0 * &q0;
        let num_bigint: BigInt = BigInt::from_bytes_be(Sign::Plus, &num.to_bytes());
        let num_bignum: BigNumber = BigNumber::from_slice(&num_bigint.to_bytes_be().1);
        assert!(num == num_bignum);
        assert!(num.to_string() == num_bigint.to_string());
        Ok(())
    }
}
