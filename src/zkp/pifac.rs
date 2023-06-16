// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof that the modulus N can be factored into
//! two numbers greater than `2^ℓ` for a parameter ell where `ℓ` is
//! [`parameters::ELL`](crate::parameters::ELL).
//!
//! The proof is defined in Figure 28 of CGGMP[^cite], and uses a standard
//! Fiat-Shamir transformation to make the proof non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! [EPrint archive, 2021](https://eprint.iacr.org/2021/060.pdf).

use crate::{
    errors::*,
    parameters::{ELL, EPSILON},
    ring_pedersen::{Commitment, CommitmentRandomness, MaskedRandomness, VerifiedRingPedersen},
    utils::{plusminus_challenge_from_transcript, random_plusminus_scaled},
    zkp::{Proof, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use num_bigint::{BigInt, Sign};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use zeroize::ZeroizeOnDrop;

/// Proof that the modulus N can be factored into two numbers greater than 2^ell
/// for a parameter ell.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct PiFacProof {
    /// Commitment to the factor `p` (`P` in the paper)
    p_commitment: Commitment,
    /// Commitment to the factor q using randomness neu.
    q_commitment: Commitment,
    /// Commitment to randomness alpha and x.
    p_mask_commitment: Commitment,
    /// Commitment to randomness beta and y.
    q_mask_commitment: Commitment,
    /// Combination of commitment to Q using ring Pedersen parameter r.
    // Commitment to q + p's commitment randomness
    q_link_commitment: Commitment,
    /// Randomness for commitment.
    sigma: CommitmentRandomness,
    /// Mask p with randomness alpha.
    p_masked: BigNumber,
    /// Mask q with randomness beta.
    q_masked: BigNumber,
    /// Mask meu with randomness x.
    masked_p_commitment_randomness: MaskedRandomness,
    /// Mask neu with randomness y.
    masked_q_commitment_randomness: MaskedRandomness,
    // Masked (p + q's commitment randomness)
    masked_p_link: MaskedRandomness,
}

/// Common input and setup parameters known to both the prover and verifier.
#[derive(Serialize)]
pub(crate) struct CommonInput {
    setup_params: VerifiedRingPedersen,
    modulus: BigNumber,
}

impl CommonInput {
    /// Generate public input for proving and verifying [`PiFacProof`] about N.
    pub(crate) fn new(setup_params: &VerifiedRingPedersen, N0: &BigNumber) -> Self {
        Self {
            setup_params: setup_params.clone(),
            modulus: N0.clone(),
        }
    }
}

/// The prover's secret knowledge: the factors `p` and `q` of the modulus `N`
/// where `N = pq`.
#[derive(ZeroizeOnDrop)]
pub(crate) struct ProverSecret {
    p: BigNumber,
    q: BigNumber,
}

impl Debug for ProverSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("pifac::Secret")
            .field("p", &"[redacted]")
            .field("q", &"[redacted]")
            .finish()
    }
}

impl ProverSecret {
    pub(crate) fn new(p: &BigNumber, q: &BigNumber) -> Self {
        Self {
            p: p.clone(),
            q: q.clone(),
        }
    }
}

impl Proof for PiFacProof {
    type CommonInput = CommonInput;
    type ProverSecret = ProverSecret;
    #[cfg_attr(feature = "flame_it", flame("PiFacProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Small names for scaling factors in our ranges
        let sqrt_N0 = &sqrt(&input.modulus);

        let alpha = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0);
        let beta = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0);

        let sigma = input
            .setup_params
            .scheme()
            .commitment_randomness(ELL, &input.modulus, rng);

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
            &input.modulus,
            rng,
        );

        Self::fill_transcript(transcript, context, input, &P, &Q, &A, &B, &T, &sigma)?;

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_challenge_from_transcript(transcript)?;

        let sigma_hat = nu.mask_neg(&sigma, &secret.p);
        let z1 = &alpha + &e * &secret.p;
        let z2 = &beta + &e * &secret.q;
        let w1 = mu.mask(&x, &e);
        let w2 = nu.mask(&y, &e);
        let v = sigma_hat.remask(&r, &e);

        let proof = Self {
            p_commitment: P,
            q_commitment: Q,
            p_mask_commitment: A,
            q_mask_commitment: B,
            q_link_commitment: T,
            sigma,
            p_masked: z1,
            q_masked: z2,
            masked_p_commitment_randomness: w1,
            masked_q_commitment_randomness: w2,
            masked_p_link: v,
        };
        Ok(proof)
    }

    fn verify(
        &self,
        input: &Self::CommonInput,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        Self::fill_transcript(
            transcript,
            context,
            input,
            &self.p_commitment,
            &self.q_commitment,
            &self.p_mask_commitment,
            &self.q_mask_commitment,
            &self.q_link_commitment,
            &self.sigma,
        )?;

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_challenge_from_transcript(transcript)?;

        let masked_p_commitment_is_valid = {
            let lhs = input
                .setup_params
                .scheme()
                .reconstruct(&self.p_masked, &self.masked_p_commitment_randomness);
            let rhs =
                input
                    .setup_params
                    .scheme()
                    .combine(&self.p_mask_commitment, &self.p_commitment, &e);
            lhs == rhs
        };
        if !masked_p_commitment_is_valid {
            error!("eq_check_1 failed");
            return Err(InternalError::ProtocolError);
        }

        let masked_q_commitment_is_valid = {
            let lhs = input
                .setup_params
                .scheme()
                .reconstruct(&self.q_masked, &self.masked_q_commitment_randomness);
            let rhs =
                input
                    .setup_params
                    .scheme()
                    .combine(&self.q_mask_commitment, &self.q_commitment, &e);
            lhs == rhs
        };
        if !masked_q_commitment_is_valid {
            error!("eq_check_2 failed");
            return Err(InternalError::ProtocolError);
        }

        let modulus_links_provided_factors = {
            let R = input
                .setup_params
                .scheme()
                .reconstruct(&input.modulus, self.sigma.as_masked());
            let lhs = input.setup_params.scheme().reconstruct_with_commitment(
                &self.q_commitment,
                &self.p_masked,
                &self.masked_p_link,
            );
            let rhs = input
                .setup_params
                .scheme()
                .combine(&self.q_link_commitment, &R, &e);
            lhs == rhs
        };
        if !modulus_links_provided_factors {
            error!("eq_check_3 failed");
            return Err(InternalError::ProtocolError);
        }

        let sqrt_N0 = sqrt(&input.modulus);
        // 2^{ELL + EPSILON}
        let two_ell_eps = BigNumber::one() << (ELL + EPSILON);
        // 2^{ELL + EPSILON} * sqrt(N_0)
        let z_bound = &sqrt_N0 * &two_ell_eps;
        if self.p_masked < -z_bound.clone() || self.p_masked > z_bound {
            error!("self.z1 > z_bound check failed");
            return Err(InternalError::ProtocolError);
        }
        if self.q_masked < -z_bound.clone() || self.q_masked > z_bound {
            error!("self.z2 > z_bound check failed");
            return Err(InternalError::ProtocolError);
        }

        Ok(())
    }
}

impl PiFacProof {
    #[allow(clippy::too_many_arguments)]
    fn fill_transcript(
        transcript: &mut Transcript,
        context: &impl ProofContext,
        input: &CommonInput,
        P: &Commitment,
        Q: &Commitment,
        A: &Commitment,
        B: &Commitment,
        T: &Commitment,
        sigma: &CommitmentRandomness,
    ) -> Result<()> {
        transcript.append_message(b"PiFac ProofContext", &context.as_bytes()?);
        transcript.append_message(b"PiFac CommonInput", &serialize!(&input)?);
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

#[cfg(test)]
mod tests {
    use crate::{paillier::prime_gen, utils::testing::init_testing, zkp::BadContext};

    use super::*;

    fn random_no_small_factors_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(CommonInput, PiFacProof)> {
        let (p0, q0) = prime_gen::get_prime_pair_from_pool_insecure(rng).unwrap();
        let N0 = &p0 * &q0;
        let setup_params = VerifiedRingPedersen::gen(rng, &())?;

        let mut transcript = Transcript::new(b"PiFac Test");
        let input = CommonInput::new(&setup_params, &N0);
        let proof = PiFacProof::prove(
            &input,
            &ProverSecret::new(&p0, &q0),
            &(),
            &mut transcript,
            rng,
        )?;

        Ok((input, proof))
    }

    #[test]
    fn pifac_proof_context_must_be_correct() -> Result<()> {
        let mut rng = init_testing();

        let context = BadContext {};
        let (input, proof) = random_no_small_factors_proof(&mut rng).unwrap();
        let mut transcript = Transcript::new(b"PiFacProof");
        let result = proof.verify(&input, &context, &mut transcript);
        assert!(result.is_err());
        Ok(())
    }
    #[test]
    fn test_no_small_factors_proof() -> Result<()> {
        let mut rng = init_testing();

        let (input, proof) = random_no_small_factors_proof(&mut rng)?;
        let mut transcript = Transcript::new(b"PiFac Test");
        proof.verify(&input, &(), &mut transcript)?;
        Ok(())
    }

    #[test]
    fn test_no_small_factors_proof_negative_cases() -> Result<()> {
        let mut rng = init_testing();
        let (input, proof) = random_no_small_factors_proof(&mut rng)?;

        {
            let incorrect_N = CommonInput::new(
                &input.setup_params,
                &prime_gen::try_get_prime_from_pool_insecure(&mut rng).unwrap(),
            );
            let mut transcript = Transcript::new(b"PiFac Test");
            assert!(proof.verify(&incorrect_N, &(), &mut transcript).is_err());
        }
        {
            let incorrect_startup_params =
                CommonInput::new(&VerifiedRingPedersen::gen(&mut rng, &())?, &input.modulus);
            let mut transcript = Transcript::new(b"PiFac Test");
            assert!(proof
                .verify(&incorrect_startup_params, &(), &mut transcript)
                .is_err());
        }
        {
            let mut transcript = Transcript::new(b"PiFac Test");
            let (not_p0, not_q0) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
            let incorrect_factors = PiFacProof::prove(
                &input,
                &ProverSecret::new(&not_p0, &not_q0),
                &(),
                &mut transcript,
                &mut rng,
            )?;
            let mut transcript = Transcript::new(b"PiFac Test");
            assert!(incorrect_factors
                .verify(&input, &(), &mut transcript)
                .is_err());

            let mut transcript = Transcript::new(b"PiFac Test");
            let small_p = BigNumber::from(7u64);
            let small_q = BigNumber::from(11u64);
            let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
            let small_input = CommonInput::new(&setup_params, &(&small_p * &small_q));
            let small_proof = PiFacProof::prove(
                &input,
                &ProverSecret::new(&small_p, &small_q),
                &(),
                &mut transcript,
                &mut rng,
            )?;
            let mut transcript = Transcript::new(b"PiFac Test");
            assert!(small_proof
                .verify(&small_input, &(), &mut transcript)
                .is_err());

            let mut transcript = Transcript::new(b"PiFac Test");
            let regular_sized_q = prime_gen::try_get_prime_from_pool_insecure(&mut rng).unwrap();
            let mixed_input = CommonInput::new(&setup_params, &(&small_p * &regular_sized_q));
            let mixed_proof = PiFacProof::prove(
                &input,
                &ProverSecret::new(&small_p, &regular_sized_q),
                &(),
                &mut transcript,
                &mut rng,
            )?;
            let mut transcript = Transcript::new(b"PiFac Test");
            assert!(mixed_proof
                .verify(&mixed_input, &(), &mut transcript)
                .is_err());

            let mut transcript = Transcript::new(b"PiFac Test");
            let small_fac_p = &not_p0 * &BigNumber::from(2u64);
            let small_fac_input =
                CommonInput::new(&setup_params, &(&small_fac_p * &regular_sized_q));
            let small_fac_proof = PiFacProof::prove(
                &input,
                &ProverSecret::new(&small_fac_p, &regular_sized_q),
                &(),
                &mut transcript,
                &mut rng,
            )?;
            let mut transcript = Transcript::new(b"PiFac Test");
            assert!(small_fac_proof
                .verify(&small_fac_input, &(), &mut transcript)
                .is_err());
        }

        Ok(())
    }

    #[test]
    // Make sure the bytes representations for BigNum and BigInt
    // didn't change in a way that would mess up the sqrt funtion
    fn test_bignum_bigint_byte_representation() -> Result<()> {
        let mut rng = init_testing();
        let (p0, q0) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();

        let num = &p0 * &q0;
        let num_bigint: BigInt = BigInt::from_bytes_be(Sign::Plus, &num.to_bytes());
        let num_bignum: BigNumber = BigNumber::from_slice(num_bigint.to_bytes_be().1);
        assert_eq!(num, num_bignum);
        assert_eq!(num.to_string(), num_bigint.to_string());
        Ok(())
    }
}
