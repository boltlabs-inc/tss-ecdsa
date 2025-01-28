// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof that the modulus `N` can be factored into
//! two numbers greater than `2^ℓ`, where `ℓ` is a fixed parameter defined by
//! [`parameters::ELL`](crate::parameters::ELL).
//!
//! The proof is defined in Figure 28 of CGGMP[^cite], and uses a standard
//! Fiat-Shamir transformation to make the proof non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! [EPrint archive, 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf).

use crate::{
    curve::CurveTrait,
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

/// Proof that the modulus `N` can be factored into two numbers greater than
/// `2^ℓ` for a parameter `ℓ`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct PiFacProof<C: CurveTrait> {
    /// Commitment to the factor `p` (`P` in the paper).
    p_commitment: Commitment,
    /// Commitment to the factor `q` (`Q` in the paper).
    q_commitment: Commitment,
    /// Commitment to a mask for p (`A` in the paper).
    p_mask_commitment: Commitment,
    /// Commitment to a mask for q (`B` in the paper).
    q_mask_commitment: Commitment,
    /// Commitment linking `q` to the commitment randomness used in
    /// `p_commitment`.
    q_link_commitment: Commitment,
    /// Randomness linking `q` to `p_commitment`.
    link_randomness: CommitmentRandomness,
    /// Mask `p` (`z1` in the paper`).
    p_masked: BigNumber,
    /// Mask `q` (`z2` in the paper).
    q_masked: BigNumber,
    /// Masked commitment randomness used to form `p_commitment` (`w1` in the
    /// paper).
    masked_p_commitment_randomness: MaskedRandomness,
    /// Masked commitment randomness used to form `q_commitment` (`w2` in the
    /// paper).
    masked_q_commitment_randomness: MaskedRandomness,
    /// Masked commitment randomness linking `p` to the commitment randomness
    /// used in `q_commitment` (`v` in the paper).
    masked_p_link: MaskedRandomness,
    /// Phantom data.
    _curve: std::marker::PhantomData<C>,
}

/// Common input and setup parameters known to both the prover and verifier.
///
/// Copying/Cloning references is harmless and sometimes necessary. So we
/// implement Clone and Copy for this type.
#[derive(Serialize, Copy, Clone)]
pub(crate) struct CommonInput<'a> {
    setup_params: &'a VerifiedRingPedersen,
    modulus: &'a BigNumber,
}

impl<'a> CommonInput<'a> {
    /// Generate public input for proving and verifying [`PiFacProof`] about
    /// `N`.
    pub(crate) fn new(
        verifier_commitment_params: &'a VerifiedRingPedersen,
        prover_modulus: &'a BigNumber,
    ) -> Self {
        Self {
            setup_params: verifier_commitment_params,
            modulus: prover_modulus,
        }
    }
}

/// The prover's secret knowledge: the factors `p` and `q` of the modulus `N`
/// where `N = pq`.
///
/// Copying/Cloning references is harmless and sometimes necessary. So we
/// implement Clone and Copy for this type.
#[derive(Clone, Copy)]
pub(crate) struct ProverSecret<'a> {
    p: &'a BigNumber,
    q: &'a BigNumber,
}

impl<'a> Debug for ProverSecret<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("pifac::Secret")
            .field("p", &"[redacted]")
            .field("q", &"[redacted]")
            .finish()
    }
}

impl<'a> ProverSecret<'a> {
    pub(crate) fn new(p: &'a BigNumber, q: &'a BigNumber) -> Self {
        Self { p, q }
    }
}

impl<C: CurveTrait> Proof for PiFacProof<C> {
    type CommonInput<'a> = CommonInput<'a>;
    type ProverSecret<'a> = ProverSecret<'a>;

    #[cfg_attr(feature = "flame_it", flame("PiFacProof"))]
    fn prove<'a, R: RngCore + CryptoRng>(
        input: Self::CommonInput<'a>,
        secret: Self::ProverSecret<'a>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Small names for scaling factors in our ranges
        let sqrt_N0 = &sqrt(input.modulus);

        let p_mask = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0); // `alpha` in the paper
        let q_mask = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0); // `beta` in the paper

        let link_randomness =
            input
                .setup_params
                .scheme()
                .commitment_randomness(ELL, input.modulus, rng);

        let (p_commitment, mu) = input.setup_params.scheme().commit(secret.p, ELL, rng);
        let (q_commitment, nu) = input.setup_params.scheme().commit(secret.q, ELL, rng);
        let (p_mask_commitment, x) =
            input
                .setup_params
                .scheme()
                .commit(&p_mask, ELL + EPSILON, rng);
        let (q_mask_commitment, y) =
            input
                .setup_params
                .scheme()
                .commit(&q_mask, ELL + EPSILON, rng);
        let (q_link_commitment, r) = input.setup_params.scheme().commit_with_commitment(
            &q_commitment,
            &p_mask,
            ELL + EPSILON,
            input.modulus,
            rng,
        );

        Self::fill_transcript(
            transcript,
            context,
            &input,
            &p_commitment,
            &q_commitment,
            &p_mask_commitment,
            &q_mask_commitment,
            &q_link_commitment,
            &link_randomness,
        )?;

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_challenge_from_transcript::<C>(transcript)?;

        let sigma_hat = nu.mask_neg(&link_randomness, secret.p);
        let p_masked = &p_mask + &e * secret.p;
        let q_masked = &q_mask + &e * secret.q;
        let masked_p_commitment_randomness = mu.mask(&x, &e);
        let masked_q_commitment_randomness = nu.mask(&y, &e);
        let masked_p_link = sigma_hat.remask(&r, &e);

        let proof = Self {
            p_commitment,
            q_commitment,
            p_mask_commitment,
            q_mask_commitment,
            q_link_commitment,
            link_randomness,
            p_masked,
            q_masked,
            masked_p_commitment_randomness,
            masked_q_commitment_randomness,
            masked_p_link,
            _curve: std::marker::PhantomData,
        };
        Ok(proof)
    }

    fn verify(
        self,
        input: Self::CommonInput<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        Self::fill_transcript(
            transcript,
            context,
            &input,
            &self.p_commitment,
            &self.q_commitment,
            &self.p_mask_commitment,
            &self.q_mask_commitment,
            &self.q_link_commitment,
            &self.link_randomness,
        )?;

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_challenge_from_transcript::<C>(transcript)?;

        let masked_p_commitment_is_valid = {
            let lhs = input
                .setup_params
                .scheme()
                .reconstruct(&self.p_masked, &self.masked_p_commitment_randomness);
            let rhs = input.setup_params.scheme().combine(
                &self.p_mask_commitment,
                &self.p_commitment,
                &e,
            );
            lhs == rhs
        };
        if !masked_p_commitment_is_valid {
            error!("masked_p_commitment_is_valid failed");
            return Err(InternalError::ProtocolError(None));
        }

        let masked_q_commitment_is_valid = {
            let lhs = input
                .setup_params
                .scheme()
                .reconstruct(&self.q_masked, &self.masked_q_commitment_randomness);
            let rhs = input.setup_params.scheme().combine(
                &self.q_mask_commitment,
                &self.q_commitment,
                &e,
            );
            lhs == rhs
        };
        if !masked_q_commitment_is_valid {
            error!("masked_q_commitment_is_valid failed");
            return Err(InternalError::ProtocolError(None));
        }

        let modulus_links_provided_factors = {
            let reconstructed_commitment = input
                .setup_params
                .scheme()
                .reconstruct(input.modulus, self.link_randomness.as_masked());
            let lhs = input.setup_params.scheme().reconstruct_with_commitment(
                &self.q_commitment,
                &self.p_masked,
                &self.masked_p_link,
            );
            let rhs = input.setup_params.scheme().combine(
                &self.q_link_commitment,
                &reconstructed_commitment,
                &e,
            );
            lhs == rhs
        };
        if !modulus_links_provided_factors {
            error!("modulus_links_provided_factors failed");
            return Err(InternalError::ProtocolError(None));
        }

        let sqrt_modulus = sqrt(input.modulus);
        // 2^{ELL + EPSILON}
        let two_ell_eps = BigNumber::one() << (ELL + EPSILON);
        // 2^{ELL + EPSILON} * sqrt(N_0)
        let z_bound = &sqrt_modulus * &two_ell_eps;
        if self.p_masked < -z_bound.clone() || self.p_masked > z_bound {
            error!("p is out of range!");
            return Err(InternalError::ProtocolError(None));
        }
        if self.q_masked < -z_bound.clone() || self.q_masked > z_bound {
            error!("q is out of range!");
            return Err(InternalError::ProtocolError(None));
        }
        Ok(())
    }
}

impl<C: CurveTrait> PiFacProof<C> {
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
    use crate::{
        curve::{CurveTrait, TestCurve},
        paillier::prime_gen,
        utils::{random_positive_bn, testing::init_testing},
        zkp::BadContext,
    };
    use rand::{prelude::StdRng, Rng, SeedableRng};

    use super::*;

    fn transcript() -> Transcript {
        Transcript::new(b"PiFac Test")
    }

    fn with_random_no_small_factors_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        mut test_code: impl FnMut(CommonInput, PiFacProof<TestCurve>) -> Result<()>,
    ) -> Result<()> {
        let (p0, q0) = prime_gen::get_prime_pair_from_pool_insecure(rng).unwrap();
        let N0 = &p0 * &q0;
        let setup_params = VerifiedRingPedersen::gen(rng, &())?;

        let input = CommonInput::new(&setup_params, &N0);
        let proof = PiFacProof::prove(
            input,
            ProverSecret::new(&p0, &q0),
            &(),
            &mut transcript(),
            rng,
        )?;

        test_code(input, proof)
    }

    #[test]
    fn pifac_proof_context_must_be_correct() -> Result<()> {
        let mut rng = init_testing();

        let f = |input: CommonInput, proof: PiFacProof<TestCurve>| {
            let result = proof.verify(input, &BadContext {}, &mut transcript());
            assert!(result.is_err());
            Ok(())
        };
        with_random_no_small_factors_proof(&mut rng, f)
    }

    #[test]
    fn test_no_small_factors_proof() -> Result<()> {
        let mut rng = init_testing();
        let test_code = |input: CommonInput, proof: PiFacProof<TestCurve>| {
            proof.verify(input, &(), &mut transcript())?;
            Ok(())
        };
        with_random_no_small_factors_proof(&mut rng, test_code)
    }

    #[test]
    fn modulus_common_input_must_be_same_proving_and_verifying() -> Result<()> {
        let mut rng = init_testing();
        // `rng` will be borrowed. We make another rng to be captured by the closure.
        let mut rng2 = StdRng::from_seed(rng.gen());

        // Modulus in the common input must be the same for proof creation and
        // validation.
        let modulus_must_match = |input: CommonInput, proof: PiFacProof<TestCurve>| {
            let modulus = prime_gen::try_get_prime_from_pool_insecure(&mut rng2).unwrap();
            let incorrect_N = CommonInput::new(input.setup_params, &modulus);
            assert!(proof.verify(incorrect_N, &(), &mut transcript()).is_err());
            Ok(())
        };
        with_random_no_small_factors_proof(&mut rng, modulus_must_match)
    }

    #[test]
    fn setup_params_common_input_must_be_same_proving_and_verifying() -> Result<()> {
        let mut rng = init_testing();
        // Setup parameters in the common input must be the same at proof creation and
        // verification.
        let setup_params_must_match = |input: CommonInput, proof: PiFacProof<TestCurve>| {
            let mut rng = init_testing();
            let setup_param = VerifiedRingPedersen::gen(&mut rng, &())?;
            let incorrect_startup_params = CommonInput::new(&setup_param, input.modulus);
            assert!(proof
                .verify(incorrect_startup_params, &(), &mut transcript())
                .is_err());
            Ok(())
        };
        with_random_no_small_factors_proof(&mut rng, setup_params_must_match)
    }

    #[test]
    fn test_secret_input_factors_not_correct_factors_of_modulus() -> Result<()> {
        let mut rng = init_testing();
        // `rng` will be borrowed. We make another rng to be captured by the closure.
        let mut rng2 = StdRng::from_seed(rng.gen());
        // Prover secret must have correct factors for the modulus in the common input.
        let correct_factors = |input: CommonInput, _proof: PiFacProof<TestCurve>| {
            let (not_p0, not_q0) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng2).unwrap();
            let incorrect_factors: PiFacProof<TestCurve> = PiFacProof::<TestCurve>::prove(
                input,
                ProverSecret::new(&not_p0, &not_q0),
                &(),
                &mut transcript(),
                &mut rng2,
            )?;

            assert!(incorrect_factors
                .verify(input, &(), &mut transcript())
                .is_err());

            // Factors cannot be smaller than the regular range.
            let small_p = BigNumber::from(7u64);
            let small_q = BigNumber::from(11u64);
            let small_proof: PiFacProof<TestCurve> = PiFacProof::prove(
                input,
                ProverSecret::new(&small_p, &small_q),
                &(),
                &mut transcript(),
                &mut rng2,
            )?;

            assert!(small_proof.verify(input, &(), &mut transcript()).is_err());

            // Both of the factors must correspond to the modulus and cannot be smaller than
            // the regular range.
            let regular_sized_q = prime_gen::try_get_prime_from_pool_insecure(&mut rng2).unwrap();
            let mixed_proof: PiFacProof<TestCurve> = PiFacProof::prove(
                input,
                ProverSecret::new(&small_p, &regular_sized_q),
                &(),
                &mut transcript(),
                &mut rng2,
            )?;

            assert!(mixed_proof.verify(input, &(), &mut transcript()).is_err());

            let regular_sized_p = prime_gen::try_get_prime_from_pool_insecure(&mut rng2).unwrap();
            let mixed_proof: PiFacProof<TestCurve> = PiFacProof::prove(
                input,
                ProverSecret::new(&regular_sized_p, &small_q),
                &(),
                &mut transcript(),
                &mut rng2,
            )?;

            assert!(mixed_proof.verify(input, &(), &mut transcript()).is_err());

            Ok(())
        };
        with_random_no_small_factors_proof(&mut rng, correct_factors)
    }

    #[test]
    fn test_modulus_cannot_have_large_factors() -> Result<()> {
        let mut rng = init_testing();
        let (regular_sized_p, regular_sized_q) =
            prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;

        let small_factor = BigNumber::from(2u64);
        let large_factor = &regular_sized_p * &regular_sized_q;
        let modulus = &small_factor * &large_factor;

        let small_fac_input = CommonInput::new(&setup_params, &modulus);
        let small_fac_proof: PiFacProof<TestCurve> = PiFacProof::prove(
            small_fac_input,
            ProverSecret::new(&small_factor, &large_factor),
            &(),
            &mut transcript(),
            &mut rng,
        )?;

        assert!(small_fac_proof
            .verify(small_fac_input, &(), &mut transcript())
            .is_err());

        let small_fac_proof: PiFacProof<TestCurve> = PiFacProof::prove(
            small_fac_input,
            ProverSecret::new(&large_factor, &small_factor),
            &(),
            &mut transcript(),
            &mut rng,
        )?;

        assert!(small_fac_proof
            .verify(small_fac_input, &(), &mut transcript())
            .is_err());

        Ok(())
    }

    #[test]
    fn proof_elements_should_be_correct() -> Result<()> {
        let mut rng = init_testing();
        // `rng` will be borrowed. We make another rng to be captured by the closure.
        let mut rng2 = StdRng::from_seed(rng.gen());
        let proof_elements_must_be_correct = |input: CommonInput, proof: PiFacProof<TestCurve>| {
            let mut incorrect_proof = proof.clone();
            let random_bignumber = random_positive_bn(&mut rng, &TestCurve::order());
            incorrect_proof.p_masked = random_bignumber.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());
            let mut incorrect_proof = proof.clone();

            incorrect_proof.q_masked = random_bignumber.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());

            let mut incorrect_proof = proof.clone();
            let scheme = VerifiedRingPedersen::gen(&mut rng, &())?;
            let (random_commitment, _) = scheme.scheme().commit(&random_bignumber, ELL, &mut rng);
            incorrect_proof.p_commitment = random_commitment.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());

            let mut incorrect_proof = proof.clone();
            incorrect_proof.q_commitment = random_commitment.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());

            let mut incorrect_proof = proof.clone();
            let (random_commitment, random_commmitment_randomness) =
                scheme
                    .scheme()
                    .commit(&random_bignumber, ELL + EPSILON, &mut rng);
            incorrect_proof.p_mask_commitment = random_commitment.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());

            let mut incorrect_proof = proof.clone();
            incorrect_proof.q_mask_commitment = random_commitment.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());

            let (q_link_commitment, _) = input.setup_params.scheme().commit_with_commitment(
                &proof.q_commitment,
                &proof.p_masked,
                ELL + EPSILON,
                input.modulus,
                &mut rng,
            );
            let mut incorrect_proof = proof.clone();
            incorrect_proof.q_link_commitment = q_link_commitment;
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());
            let mut incorrect_proof = proof.clone();
            incorrect_proof.link_randomness = random_commmitment_randomness.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());

            let mut incorrect_proof = proof.clone();
            let random_masked_randomness = random_commmitment_randomness.as_masked();
            incorrect_proof.masked_p_commitment_randomness = random_masked_randomness.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());

            let mut incorrect_proof = proof.clone();
            incorrect_proof.masked_q_commitment_randomness = random_masked_randomness.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());

            let mut incorrect_proof = proof.clone();
            incorrect_proof.masked_p_link = random_masked_randomness.clone();
            assert!(incorrect_proof
                .verify(input, &(), &mut transcript())
                .is_err());
            Ok(())
        };
        with_random_no_small_factors_proof(&mut rng2, proof_elements_must_be_correct)
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
