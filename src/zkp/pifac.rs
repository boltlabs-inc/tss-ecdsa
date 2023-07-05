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

/// Proof that the modulus `N` can be factored into two numbers greater than
/// `2^ℓ` for a parameter `ℓ`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct PiFacProof {
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
    /// Randomness for commitment.
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
}

/// Common input and setup parameters known to both the prover and verifier.
#[derive(Serialize)]
pub(crate) struct CommonInput {
    setup_params: VerifiedRingPedersen,
    modulus: BigNumber,
}

impl CommonInput {
    /// Generate public input for proving and verifying [`PiFacProof`] about
    /// `N`.
    pub(crate) fn new(
        verifier_commitment_params: &VerifiedRingPedersen,
        prover_modulus: &BigNumber,
    ) -> Self {
        Self {
            setup_params: verifier_commitment_params.clone(),
            modulus: prover_modulus.clone(),
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

        let p_mask = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0); // `alpha` in the paper
        let q_mask = random_plusminus_scaled(rng, ELL + EPSILON, sqrt_N0); // `beta` in the paper

        let link_randomness =
            input
                .setup_params
                .scheme()
                .commitment_randomness(ELL, &input.modulus, rng);

        let (p_commitment, mu) = input.setup_params.scheme().commit(&secret.p, ELL, rng);
        let (q_commitment, nu) = input.setup_params.scheme().commit(&secret.q, ELL, rng);
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
            &input.modulus,
            rng,
        );

        Self::fill_transcript(
            transcript,
            context,
            input,
            &p_commitment,
            &q_commitment,
            &p_mask_commitment,
            &q_mask_commitment,
            &q_link_commitment,
            &link_randomness,
        )?;

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_challenge_from_transcript(transcript)?;

        let sigma_hat = nu.mask_neg(&link_randomness, &secret.p);
        let p_masked = &p_mask + &e * &secret.p;
        let q_masked = &q_mask + &e * &secret.q;
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
            &self.link_randomness,
        )?;

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_challenge_from_transcript(transcript)?;

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
            return Err(InternalError::ProtocolError);
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
            return Err(InternalError::ProtocolError);
        }

        let modulus_links_provided_factors = {
            let reconstructed_commitment = input
                .setup_params
                .scheme()
                .reconstruct(&input.modulus, self.link_randomness.as_masked());
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
            return Err(InternalError::ProtocolError);
        }

        if crate::utils::within_bound_by_size(&self.p_masked, ELL + EPSILON) {
            error!("p is out of range!");
            return Err(InternalError::ProtocolError);
        }
        if crate::utils::within_bound_by_size(&self.q_masked, ELL + EPSILON) {
            error!("q is out of range!");
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
