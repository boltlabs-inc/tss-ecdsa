// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof that [`RingPedersen`] parameters were correctly
//! constructed.
//!
//! In more detail, a valid [`RingPedersen`] object is compromised of a tuple `(N, s, t)`
//! such that `s = t^λ mod N` for some secret `λ`. This module implements a zero-knowledge
//! proof of this fact. The proof is defined in Figure 17 of CGGMP[^cite].
//!
//! This proof utilizes the soundness parameter as specified [here](crate::parameters::SOUNDNESS_PARAMETER).
//! In addition, it uses a standard Fiat-Shamir transformation to make the proof non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! [EPrint archive, 2021](https://eprint.iacr.org/2021/060.pdf).

use super::Proof;
use crate::{errors::*, ring_pedersen::RingPedersen, utils::*};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// Soundness parameter.
const SOUNDNESS: usize = crate::parameters::SOUNDNESS_PARAMETER;

/// Proof that externally provided [`RingPedersen`] parameters are constructed correctly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiPrmProof {
    /// The commitments computed by the prover (`A_i` in the paper).
    commitments: Vec<BigNumber>,
    /// The randomized challenge bytes (`e_i` in the paper).
    challenge_bytes: Vec<u8>,
    /// The prover responses (`z_i` in the paper).
    responses: Vec<BigNumber>,
}

/// The prover's secret knowledge.
///
/// This is comprised of two components:
/// 1. The secret exponent used when generating the [`RingPedersen`] parameters.
/// 2. Euler's totient of [`RingPedersen::modulus`].
pub(crate) struct PiPrmSecret {
    /// The secret exponent that correlates [`RingPedersen`] parameters
    /// [`s`](RingPedersen::s) and [`t`](RingPedersen::t).
    exponent: BigNumber,
    /// Euler's totient of [`RingPedersen::modulus`].
    totient: BigNumber,
}

impl PiPrmSecret {
    /// Collect the secret knowledge for proving [`PiPrmProof`].
    pub(crate) fn new(exponent: BigNumber, totient: BigNumber) -> Self {
        Self { exponent, totient }
    }
}

/// Generates challenge bytes from the proof transcript using the Fiat-Shamir transform.
/// Used by the prover and the verifier.
fn generate_challenge_bytes(input: &RingPedersen, commitments: &[BigNumber]) -> Result<Vec<u8>> {
    // Construct a transcript for the Fiat-Shamir transform.
    let mut transcript = Transcript::new(b"PiPrmProof");
    transcript.append_message(b"Common input", &serialize!(&input)?);
    transcript.append_message(b"Commitments", &serialize!(&commitments)?);
    // Extract challenge bytes from the transcript.
    let mut challenges = [0u8; SOUNDNESS];
    transcript.challenge_bytes(b"Challenges", challenges.as_mut_slice());
    Ok(challenges.into())
}

impl Proof for PiPrmProof {
    type CommonInput = RingPedersen;
    type ProverSecret = PiPrmSecret;

    #[cfg_attr(feature = "flame_it", flame("PiPrmProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // Sample secret exponents `a_i ← Z[ɸ(N)]`.
        let secret_exponents: Vec<_> =
            std::iter::repeat_with(|| random_positive_bn(rng, &secret.totient))
                .take(SOUNDNESS)
                .collect();
        // Compute commitments values `A_i = t^{a_i} mod N`.
        let commitments = secret_exponents
            .iter()
            .map(|a| modpow(input.t(), a, input.modulus()))
            .collect::<Vec<_>>();
        let challenge_bytes = generate_challenge_bytes(input, &commitments)?;
        // Compute challenge responses `z_i = a_i + e_i λ mod ɸ(N)`.
        let responses = challenge_bytes
            .iter()
            .zip(secret_exponents)
            .map(|(e, a)| {
                if e % 2 == 1 {
                    a.modadd(&secret.exponent, &secret.totient)
                } else {
                    a
                }
            })
            .collect();

        Ok(Self {
            commitments,
            challenge_bytes,
            responses,
        })
    }

    #[cfg_attr(feature = "flame_it", flame("PiPrmProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // Check that all the lengths equal the soundness parameter.
        if self.commitments.len() != SOUNDNESS
            || self.challenge_bytes.len() != SOUNDNESS
            || self.responses.len() != SOUNDNESS
        {
            return verify_err!("length of values provided does not match soundness parameter");
        }
        let challenges = generate_challenge_bytes(input, &self.commitments)?;
        // Check Fiat-Shamir consistency.
        if challenges != self.challenge_bytes.as_slice() {
            return verify_err!("Fiat-Shamir does not verify");
        }

        let is_sound = challenges
            .into_iter()
            .zip(&self.responses)
            .zip(&self.commitments)
            .map(|((e, z), a)| {
                // Verify that `t^{z_i} = {A_i} * s^{e_i} mod N`.
                let lhs = modpow(input.t(), z, input.modulus());
                let rhs = if e % 2 == 1 {
                    a.modmul(input.s(), input.modulus())
                } else {
                    a.clone()
                };
                lhs == rhs
            })
            .all(|check| check);

        if !is_sound {
            return verify_err!("response validation check failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::paillier::prime_gen;

    use super::*;

    fn random_ring_pedersen_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(RingPedersen, PiPrmProof)> {
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(rng).unwrap();
        let N = &p * &q;
        let phi_n = (p - 1) * (q - 1);
        let tau = BigNumber::from_rng(&N, rng);
        let lambda = BigNumber::from_rng(&phi_n, rng);
        let t = modpow(&tau, &BigNumber::from(2), &N);
        let s = modpow(&t, &lambda, &N);

        let ring_pedersen = RingPedersen::from_parts(s, t, N);
        let proof = PiPrmProof::prove(rng, &ring_pedersen, &PiPrmSecret::new(lambda, phi_n))?;
        Ok((ring_pedersen, proof))
    }

    #[test]
    fn test_ring_pedersen_proof() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
        let (input, proof) = random_ring_pedersen_proof(&mut rng)?;
        proof.verify(&input)?;

        Ok(())
    }

    #[test]
    fn test_ring_pedersen_proof_roundtrip() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
        let (_, proof) = random_ring_pedersen_proof(&mut rng)?;
        let buf = bincode::serialize(&proof).unwrap();
        let orig: PiPrmProof = bincode::deserialize(&buf).unwrap();
        assert_eq!(buf, bincode::serialize(&orig).unwrap());
        Ok(())
    }
}
