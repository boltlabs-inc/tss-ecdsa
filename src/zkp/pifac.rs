// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
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
    ring_pedersen::{Commitment, CommitmentRandomness, MaskedRandomness, VerifiedRingPedersen},
    utils::{k256_order, plusminus_bn_random_from_transcript, random_plusminus_scaled},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use num_bigint::{BigInt, Sign};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct PiFacProof {
    P: Commitment,
    Q: Commitment,
    A: Commitment,
    B: Commitment,
    T: Commitment,
    sigma: CommitmentRandomness,
    z1: BigNumber,
    z2: BigNumber,
    w1: MaskedRandomness,
    w2: MaskedRandomness,
    v: MaskedRandomness,
}

#[derive(Serialize)]
pub(crate) struct PiFacInput {
    setup_params: VerifiedRingPedersen,
    N0: BigNumber,
}

impl PiFacInput {
    pub(crate) fn new(setup_params: &VerifiedRingPedersen, N0: &BigNumber) -> Self {
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
        // Small names for scaling factors in our ranges
        let sqrt_N0 = &sqrt(&input.N0);

        let alpha = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0);
        let beta = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0);

        let sigma = input
            .setup_params
            .scheme()
            .commitment_randomness(ELL, &input.N0, rng);

        let (P, mu) = input.setup_params.scheme().commit(&secret.p, ELL, rng);
        let (Q, nu) = input.setup_params.scheme().commit(&secret.q, ELL, rng);
        let (A, x) = input
            .setup_params
            .scheme()
            .commit(&alpha, ELL + EPSILON, rng);
        let (B, y) = input
            .setup_params
            .scheme()
            .commit(&beta, ELL + EPSILON, rng);
        let (T, r) = input.setup_params.scheme().commit_with_commitment(
            &Q,
            &alpha,
            ELL + EPSILON,
            &input.N0,
            rng,
        );

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

        let sigma_hat = nu.mask_neg(&sigma, &secret.p);
        let z1 = &alpha + &e * &secret.p;
        let z2 = &beta + &e * &secret.q;
        let w1 = mu.mask(&x, &e);
        let w2 = nu.mask(&y, &e);
        let v = sigma_hat.remask(&r, &e);

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
            let lhs = input.setup_params.scheme().reconstruct(&self.z1, &self.w1);
            let rhs = input.setup_params.scheme().combine(&self.A, &self.P, &e);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let lhs = input.setup_params.scheme().reconstruct(&self.z2, &self.w2);
            let rhs = input.setup_params.scheme().combine(&self.B, &self.Q, &e);
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let R = input
                .setup_params
                .scheme()
                .reconstruct(&input.N0, self.sigma.as_masked());
            let lhs = input
                .setup_params
                .scheme()
                .reconstruct_with_commitment(&self.Q, &self.z1, &self.v);
            let rhs = input.setup_params.scheme().combine(&self.T, &R, &e);
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
    BigNumber::from_slice(sqrt.to_bytes_be().1)
}

impl PiFacProof {
    pub(crate) fn prove_with_transcript<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &PiFacInput,
        secret: &PiFacSecret,
        transcript: &mut Transcript,
    ) -> Result<Self> {
        // Small names for scaling factors in our ranges
        let sqrt_N0 = &sqrt(&input.N0);

        let alpha = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0);
        let beta = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0);

        let sigma = input
            .setup_params
            .scheme()
            .commitment_randomness(ELL, &input.N0, rng);

        let (P, mu) = input.setup_params.scheme().commit(&secret.p, ELL, rng);
        let (Q, nu) = input.setup_params.scheme().commit(&secret.q, ELL, rng);
        let (A, x) = input
            .setup_params
            .scheme()
            .commit(&alpha, ELL + EPSILON, rng);
        let (B, y) = input
            .setup_params
            .scheme()
            .commit(&beta, ELL + EPSILON, rng);
        let (T, r) = input.setup_params.scheme().commit_with_commitment(
            &Q,
            &alpha,
            ELL + EPSILON,
            &input.N0,
            rng,
        );

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

        let sigma_hat = nu.mask_neg(&sigma, &secret.p);
        let z1 = &alpha + &e * &secret.p;
        let z2 = &beta + &e * &secret.q;
        let w1 = mu.mask(&x, &e);
        let w2 = nu.mask(&y, &e);
        let v = sigma_hat.remask(&r, &e);

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
            let lhs = input.setup_params.scheme().reconstruct(&self.z1, &self.w1);
            let rhs = input.setup_params.scheme().combine(&self.A, &self.P, &e);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let lhs = input.setup_params.scheme().reconstruct(&self.z2, &self.w2);
            let rhs = input.setup_params.scheme().combine(&self.B, &self.Q, &e);
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let R = input
                .setup_params
                .scheme()
                .reconstruct(&input.N0, self.sigma.as_masked());
            let lhs = input
                .setup_params
                .scheme()
                .reconstruct_with_commitment(&self.Q, &self.z1, &self.v);
            let rhs = input.setup_params.scheme().combine(&self.T, &R, &e);
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
    use crate::paillier::prime_gen;

    use super::*;

    fn random_no_small_factors_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(PiFacInput, PiFacProof)> {
        let (p0, q0) = prime_gen::get_prime_pair_from_pool_insecure(rng).unwrap();
        let N0 = &p0 * &q0;
        let setup_params = VerifiedRingPedersen::gen(rng)?;

        let input = PiFacInput::new(&setup_params, &N0);
        let proof = PiFacProof::prove(rng, &input, &PiFacSecret::new(&p0, &q0))?;

        Ok((input, proof))
    }

    #[test]
    fn test_no_small_factors_proof() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
        let (input, proof) = random_no_small_factors_proof(&mut rng)?;
        proof.verify(&input)?;
        Ok(())
    }

    #[test]
    fn test_no_small_factors_proof_negative_cases() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
        let (input, proof) = random_no_small_factors_proof(&mut rng)?;

        let incorrect_N = PiFacInput::new(
            &input.setup_params,
            &prime_gen::try_get_prime_from_pool_insecure(&mut rng).unwrap(),
        );
        assert!(proof.verify(&incorrect_N).is_err());

        let incorrect_startup_params =
            PiFacInput::new(&VerifiedRingPedersen::gen(&mut rng)?, &input.N0);
        assert!(proof.verify(&incorrect_startup_params).is_err());

        let (not_p0, not_q0) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let incorrect_factors =
            PiFacProof::prove(&mut rng, &input, &PiFacSecret::new(&not_p0, &not_q0))?;
        assert!(incorrect_factors.verify(&input).is_err());

        let small_p = BigNumber::from(7u64);
        let small_q = BigNumber::from(11u64);
        let setup_params = VerifiedRingPedersen::gen(&mut rng)?;
        let small_input = PiFacInput::new(&setup_params, &(&small_p * &small_q));
        let small_proof =
            PiFacProof::prove(&mut rng, &input, &PiFacSecret::new(&small_p, &small_q))?;
        assert!(small_proof.verify(&small_input).is_err());

        let regular_sized_q = prime_gen::try_get_prime_from_pool_insecure(&mut rng).unwrap();
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
        let mut rng = crate::utils::get_test_rng();
        let (p0, q0) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();

        let num = &p0 * &q0;
        let num_bigint: BigInt = BigInt::from_bytes_be(Sign::Plus, &num.to_bytes());
        let num_bignum: BigNumber = BigNumber::from_slice(num_bigint.to_bytes_be().1);
        assert_eq!(num, num_bignum);
        assert_eq!(num.to_string(), num_bigint.to_string());
        Ok(())
    }
}
