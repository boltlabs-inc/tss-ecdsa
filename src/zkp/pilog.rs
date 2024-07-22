// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof that a discrete log commitment and
//! Paillier encryption contain the same underlying plaintext and that plaintext
//! falls within a given range.
//!
//! The proof is defined in Figure 25 of CGGMP[^cite], and uses a standard
//! Fiat-Shamir transformation to make the proof non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! [EPrint archive, 2021](https://eprint.iacr.org/2021/060.pdf).

use crate::{
    curve_point::{self, CurveTrait}, errors::*, paillier::{Ciphertext, EncryptionKey, MaskedNonce, Nonce}, parameters::{ELL, EPSILON}, ring_pedersen::{Commitment, MaskedRandomness, RingPedersen}, utils::{
        plusminus_challenge_from_transcript, random_plusminus_by_size, within_bound_by_size,
    }, zkp::{Proof, ProofContext}
};
use k256::elliptic_curve::Curve;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use crate::curve_point::CurvePoint;

/// Proof of knowledge that:
/// 1. the committed value in a discrete log commitment and the plaintext value
/// of a Paillier encryption are equal, and
/// 2. the plaintext value is in the valid range (in this case `± 2^{ℓ + ε}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiLogProof {
    /// Commitment to the (secret) [plaintext](ProverSecret::plaintext) (`S` in
    /// the paper).
    plaintext_commit: Commitment,
    /// Paillier encryption of mask value (`A` in the paper).
    mask_ciphertext: Ciphertext,
    /// Discrete log commitment of mask value (`Y` in the paper).
    mask_dlog_commit: CurvePoint,
    /// Ring-Pedersen commitment of mask value (`D` in the paper).
    mask_commit: Commitment,
    /// Fiat-Shamir challenge (`e` in the paper).
    challenge: BigNumber,
    /// Response binding the (secret) plaintext with the mask value
    /// (`z1` in the paper).
    plaintext_response: BigNumber,
    /// Response binding the (secret) nonce with the nonce corresponding to
    /// [`PiLogProof::mask_ciphertext`] (`z2` in the paper).
    nonce_response: MaskedNonce,
    /// Response binding the (secret) plaintext's commitment with
    /// [`PiLogProof::mask_commit`] (`z3` in the paper).
    plaintext_commit_response: MaskedRandomness,
}

/// Common input and setup parameters known to both the prover and the verifier.
///
/// Copying/Cloning references is harmless and sometimes necessary. So we
/// implement Clone and Copy for this type.
#[derive(Serialize, Clone, Copy)]
pub(crate) struct CommonInput<'a, C: CurveTrait> {
    /// Claimed ciphertext of the (secret) [plaintext](ProverSecret::plaintext)
    /// (`C` in the paper).
    ciphertext: &'a Ciphertext,
    /// Claimed discrete log commitment of the (secret)
    /// [plaintext](ProverSecret::plaintext) (`X` in the paper).
    dlog_commit: &'a C::Point,
    /// Ring-Pedersen commitment scheme (`(Nhat, s, t)` in the paper).
    ring_pedersen: &'a RingPedersen,
    /// Paillier public key (`N_0` in the paper).
    prover_encryption_key: &'a EncryptionKey,
    // Group generator for discrete log commitments (`g` in the paper).
    generator: &'a C::Point,
}

impl<'a, C: CurveTrait<Point = C>> CommonInput<'a, C> {
    /// Collect common parameters for proving or verifying a [`PiLogProof`]
    /// about `ciphertext` and `dlog_commit`.
    ///
    /// The last three arguments are shared setup information:
    /// 1. `verifier_ring_pedersen` is a [`RingPedersen`] generated
    /// by the verifier.
    /// 2. `prover_encryption_key` is a [`EncryptionKey`] generated by the
    /// prover.
    /// 3. `generator` is a group generator.
    pub(crate) fn new(
        ciphertext: &'a Ciphertext,
        dlog_commit: &'a C::Point,
        verifier_ring_pedersen: &'a RingPedersen,
        prover_encryption_key: &'a EncryptionKey,
        generator: &'a C::Point,
    ) -> CommonInput<'a, C::Point> where <C as curve_point::CurveTrait>::Point: curve_point::CurveTrait {
        Self {
            ciphertext,
            dlog_commit,
            ring_pedersen: verifier_ring_pedersen,
            prover_encryption_key,
            generator,
        }
    }
}

/// The prover's secret knowledge.
pub(crate) struct ProverSecret<'a> {
    /// The secret plaintext (`x` in the paper).
    plaintext: &'a BigNumber,
    /// The corresponding secret nonce (`ρ` in the paper).
    nonce: &'a Nonce,
}

impl<'a> Debug for ProverSecret<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("pilog::ProverSecret")
            .field("plaintext", &"[redacted]")
            .field("nonce", &"[redacted]")
            .finish()
    }
}

impl<'a> ProverSecret<'a> {
    /// Collect prover secrets for proving [`PiLogProof`].
    pub(crate) fn new(plaintext: &'a BigNumber, nonce: &'a Nonce) -> Self {
        ProverSecret { plaintext, nonce }
    }
}

/// Generates a challenge from a [`Transcript`] and the values generated in the
/// proof.
fn generate_challenge(
    transcript: &mut Transcript,
    context: &dyn ProofContext,
    common_input: CommonInput<CurvePoint>,
    plaintext_commit: &Commitment,
    mask_encryption: &Ciphertext,
    mask_dlog_commit: &CurvePoint,
    mask_commit: &Commitment,
) -> Result<BigNumber> {
    transcript.append_message(b"PiLog ProofContext", &context.as_bytes()?);
    transcript.append_message(b"PiLog Common input", &serialize!(&common_input)?);
    transcript.append_message(
        b"(plaintext commit, mask encryption, mask dlog commit, mask commit)",
        &[
            plaintext_commit.to_bytes(),
            mask_encryption.to_bytes(),
            serialize!(&mask_dlog_commit)?,
            mask_commit.to_bytes(),
        ]
        .concat(),
    );

    // The challenge is sampled from `± q` (where `q` is the group order).
    let challenge = plusminus_challenge_from_transcript(transcript)?;
    Ok(challenge)
}

impl Proof for PiLogProof {
    type CommonInput<'a, CurvePoint: curve_point::CurveTrait + 'a> = CommonInput<'a, CurvePoint>;
    type ProverSecret<'a> = ProverSecret<'a>;
    #[cfg_attr(feature = "flame_it", flame("PiLogProof"))]
    fn prove<'a, R: RngCore + CryptoRng>(
        input: Self::CommonInput<'a, CurvePoint>,
        secret: Self::ProverSecret<'a>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // The proof works as follows.
        //
        // Recall that the prover wants to prove that some public Paillier ciphertext
        // `C` and group element `X` correctly encrypts / commits a secret
        // plaintext value `x`.
        //
        // The prover begins by generating a "mask" value (denoted by `ɑ` in the paper),
        // and then commits / encrypts it in three ways:
        //
        // 1. A Paillier encryption (`A` in the paper).
        // 2. A discrete log commitment (`Y` in the paper).
        // 3. A ring-Pedersen commitment (`D` in the paper).
        //
        // In addition, the prover provides a ring-Pedersen commitment (`S` in the
        // paper) of `x`.
        //
        // The proof utilizes the homomorphic properties of these commitments /
        // encryptions to perform a bunch of checks. All of these checks utilize
        // a challenge value (`e` in the paper) produced by Fiat-Shamir-ing the
        // above commitments / encryptions.
        //
        // 1. We first check that the Paillier encryption of `ɑ + ex` equals `A C^e`;
        // this enforces that the Paillier encryption of `x` and `ɑ` "check
        // out". Note that here we need to homomorphically manipulate the
        // Paillier nonces to make sure they line up as well.
        //
        // 2. We next check that the group exponentiation of `ɑ + ex` equals `Y X^e`;
        // this enforces that the group exponentiation of `x` and `ɑ` "check
        // out".
        //
        // 3. We next check that the ring-Pedersen commitments are consistent by
        // checking that the ring-Pedersen commitment of `ɑ + ex` equals `D S^e`.
        // As in Step 1, we need to homomorphically maniuplate the commitment randomness
        // to make sure they line up. This check is needed as detailed in the "Vanilla
        // ZK Range-Proof" section of the paper (Page 13).
        //
        // 4. The last check is a range check on `ɑ + ex`. If this falls within `± 2^{ℓ
        // + ε}` then this guarantees that `x` falls within this range too.

        // Sample a random plaintext mask from `± 2^{ELL + EPSILON}` (`ɑ` in the paper).
        let mask = random_plusminus_by_size(rng, ELL + EPSILON);
        // Commit to the secret plaintext using ring-Pedersen (producing variables `S`
        // and `μ` in the paper).
        let (plaintext_commit, plaintext_commit_randomness) =
            input.ring_pedersen.commit(secret.plaintext, ELL, rng);
        // Encrypt the random plaintext using Paillier (producing variables `A` and `r`
        // in the paper).
        let (mask_ciphertext, mask_nonce) = input
            .prover_encryption_key
            .encrypt(rng, &mask)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        // Commit to the random plaintext using discrete log (`Y` in the paper).
        let mask_dlog_commit = input.generator.multiply_by_bignum(&mask)?;
        // Commit to the random plaintext using ring-Pedersen (producing variables `D`
        // and `ɣ` in the paper).
        let (mask_commit, mask_commit_randomness) =
            input.ring_pedersen.commit(&mask, ELL + EPSILON, rng);
        // Generate verifier's challenge via Fiat-Shamir (`e` in the paper).
        let challenge = generate_challenge(
            transcript,
            context,
            input,
            &plaintext_commit,
            &mask_ciphertext,
            &mask_dlog_commit,
            &mask_commit,
        )?;
        // Mask the secret plaintext (`z1` in the paper).
        let plaintext_response = &mask + &challenge * secret.plaintext;
        // Mask the secret nonce (`z2` in the paper).
        let nonce_response =
            input
                .prover_encryption_key
                .mask(secret.nonce, &mask_nonce, &challenge);
        // Mask the secret plaintext's commitment randomness (`z3` in the paper).
        let plaintext_commit_response =
            plaintext_commit_randomness.mask(&mask_commit_randomness, &challenge);

        Ok(Self {
            plaintext_commit,
            mask_ciphertext,
            mask_dlog_commit,
            mask_commit,
            challenge,
            plaintext_response,
            nonce_response,
            plaintext_commit_response,
        })
    }

    #[cfg_attr(feature = "flame_it", flame("PiLogProof"))]
    fn verify<'a>(
        self,
        input: Self::CommonInput<'_, CurvePoint>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        // See the comment in `prove` for a high-level description of how the protocol
        // works.

        // Generate verifier's challenge via Fiat-Shamir...
        let challenge = generate_challenge(
            transcript,
            context,
            input,
            &self.plaintext_commit,
            &self.mask_ciphertext,
            &self.mask_dlog_commit,
            &self.mask_commit,
        )?;
        // ... and check that it's the correct challenge.
        if challenge != self.challenge {
            error!("Fiat-Shamir consistency check failed");
            return Err(InternalError::ProtocolError(None));
        }

        // Check that the Paillier encryption of the secret plaintext is valid.
        let paillier_encryption_is_valid = {
            let lhs = input
                .prover_encryption_key
                .encrypt_with_nonce(&self.plaintext_response, &self.nonce_response)
                .map_err(|_| InternalError::ProtocolError(None))?;
            let rhs = input
                .prover_encryption_key
                .multiply_and_add(&self.challenge, input.ciphertext, &self.mask_ciphertext)
                .map_err(|_| InternalError::ProtocolError(None))?;
            lhs == rhs
        };
        if !paillier_encryption_is_valid {
            error!("paillier encryption check (first equality check) failed");
            return Err(InternalError::ProtocolError(None));
        }
        // Check that the group exponentiation of the secret plaintext is valid.
        let group_exponentiation_is_valid = {
            let lhs = input
                .generator
                .multiply_by_bignum(&self.plaintext_response)?;
            let rhs =
                self.mask_dlog_commit + input.dlog_commit.multiply_by_bignum(&self.challenge)?;
            lhs == rhs
        };
        if !group_exponentiation_is_valid {
            error!("group exponentiation check (second equality check) failed");
            return Err(InternalError::ProtocolError(None));
        }

        // Check that the ring-Pedersen commitment of the secret plaintext is valid.
        let ring_pedersen_commitment_is_valid = {
            let lhs = input
                .ring_pedersen
                .reconstruct(&self.plaintext_response, &self.plaintext_commit_response);
            let rhs = input.ring_pedersen.combine(
                &self.mask_commit,
                &self.plaintext_commit,
                &self.challenge,
            );
            lhs == rhs
        };
        if !ring_pedersen_commitment_is_valid {
            error!("ring Pedersen commitment check (third equality check) failed");
            return Err(InternalError::ProtocolError(None));
        }

        // Do a range check on the plaintext response, which validates that the
        // plaintext falls within the same range.
        if !within_bound_by_size(&self.plaintext_response, ELL + EPSILON) {
            error!("plaintext range check failed");
            return Err(InternalError::ProtocolError(None));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve_point::{testing::init_testing, CurveTrait}, paillier::{DecryptionKey, Nonce}, ring_pedersen::VerifiedRingPedersen, utils::random_plusminus_by_size_with_minimum, zkp::BadContext
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn transcript() -> Transcript {
        Transcript::new(b"PiLogProof Test")
    }

    fn with_random_paillier_log_proof<R: RngCore + CryptoRng, C: CurveTrait<Point = C>>(
        rng: &mut R,
        x: &BigNumber,
        mut f: impl FnMut(PiLogProof, CommonInput<CurvePoint>) -> Result<()>,
    ) -> Result<()> {
        let (decryption_key, _, _) = DecryptionKey::new(rng).unwrap();
        let pk = decryption_key.encryption_key();

        let g = C::generator();

        let X = g.multiply_by_bignum(x)?;
        let (ciphertext, rho) = pk.encrypt(rng, x).unwrap();

        let setup_params = VerifiedRingPedersen::gen(rng, &())?;

        let input = CommonInput::new(&ciphertext, &X, setup_params.scheme(), &pk, &g);

        let proof = PiLogProof::prove(
            input,
            ProverSecret::new(x, &rho),
            &(),
            &mut transcript(),
            rng,
        )?;
        f(proof, input)
    }

    fn random_paillier_log_proof_verification<R: RngCore + CryptoRng, C: CurveTrait<Point = C>>(
        rng: &mut R,
        x: &BigNumber,
    ) -> Result<()> {
        let f = |proof: PiLogProof, input: CommonInput<CurvePoint>| {
            proof.verify(input, &(), &mut transcript())?;
            Ok(())
        };
        with_random_paillier_log_proof::<R, C>(rng, x, f)
    }

    #[test]
    fn test_pilog_proof_with_consistent_secret_inputs_out_of_range(){
        pilog_proof_with_consistent_secret_inputs_out_of_range::<StdRng, CurvePoint>().unwrap();
    }

    fn pilog_proof_with_consistent_secret_inputs_out_of_range<R: RngCore + CryptoRng, C: CurveTrait<Point = C>>() -> Result<()> {
        let mut rng = init_testing();
        let upper_bound = BigNumber::one() << (ELL + EPSILON);
        loop {
            let too_large = random_plusminus_by_size_with_minimum(
                &mut rng,
                ELL + EPSILON + 2,
                ELL + EPSILON + 1,
            )?;

            // If the input value is larger than the top of the range, the proof won't
            // verify
            if too_large > upper_bound {
                let f = |bad_proof: PiLogProof, input: CommonInput<CurvePoint>| {
                    assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
                    Ok(())
                };
                with_random_paillier_log_proof::<StdRng, C>(&mut rng, &too_large, f)?;

                // If the value is smaller than the bottom of the range, the proof won't verify
                let too_small = -too_large;
                with_random_paillier_log_proof::<StdRng, C>(&mut rng, &too_small, f)?;
                break;
            }
        }
        Ok(())
    }

    #[test]
    fn test_pilog_proof_with_different_setup_parameters() {
        let _ = pilog_proof_with_different_setup_parameters::<CurvePoint>();
    }

    fn pilog_proof_with_different_setup_parameters<C: CurveTrait<Point = C>>() -> Result<()> {
        let mut rng = init_testing();
        let x = random_plusminus_by_size(&mut rng, ELL);
        let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let pk = decryption_key.encryption_key();
        let g = C::generator();
        let dlog_commit = g.multiply_by_bignum(&x)?;
        let (ciphertext, rho) = pk.encrypt(&mut rng, &x).unwrap();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;

        let input = CommonInput::new(&ciphertext, &dlog_commit, setup_params.scheme(), &pk, &g);

        // Generate a random encryption key
        let (bad_decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let bad_pk = bad_decryption_key.encryption_key();
        let bad_input = CommonInput::new(
            &ciphertext,
            &dlog_commit,
            setup_params.scheme(),
            &bad_pk,
            &g,
        );
        let proof = PiLogProof::prove(
            bad_input,
            ProverSecret::new(&x, &rho),
            &(),
            &mut transcript(),
            &mut rng,
        )?;
        assert!(proof.verify(bad_input, &(), &mut transcript()).is_err());

        // Generate a random generator
        let random_mask = random_plusminus_by_size(&mut rng, ELL);
        let bad_g = input.generator.multiply_by_bignum(&random_mask)?;
        let bad_input = CommonInput::new(
            &ciphertext,
            &dlog_commit,
            setup_params.scheme(),
            &pk,
            &bad_g,
        );
        let proof = PiLogProof::prove(
            bad_input,
            ProverSecret::new(&x, &rho),
            &(),
            &mut transcript(),
            &mut rng,
        )?;
        assert!(proof.verify(bad_input, &(), &mut transcript()).is_err());

        // Generate a random setup parameter
        let bad_setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let bad_input = CommonInput::new(
            &ciphertext,
            &dlog_commit,
            bad_setup_params.scheme(),
            &pk,
            &g,
        );
        let proof = PiLogProof::prove(
            bad_input,
            ProverSecret::new(&x, &rho),
            &(),
            &mut transcript(),
            &mut rng,
        )?;
        assert!(proof.verify(input, &(), &mut transcript()).is_err());

        // Swap ciphertext with a random [`Ciphertext`]
        let plaintext = random_plusminus_by_size(&mut rng, ELL);
        let (bad_ciphertext, _nonce) = input
            .prover_encryption_key
            .encrypt(&mut rng, &plaintext)
            .unwrap();
        let bad_input = CommonInput::new(
            &bad_ciphertext,
            &dlog_commit,
            setup_params.scheme(),
            &pk,
            &g,
        );
        let proof = PiLogProof::prove(
            bad_input,
            ProverSecret::new(&x, &rho),
            &(),
            &mut transcript(),
            &mut rng,
        )?;
        assert!(proof.verify(bad_input, &(), &mut transcript()).is_err());

        // Swap dlog_commit with a random [`CurvePoint`]
        let mask = random_plusminus_by_size(&mut rng, ELL);
        let bad_dlog_commit = input.generator.multiply_by_bignum(&mask)?;
        assert_ne!(&bad_dlog_commit, input.dlog_commit);
        let bad_input = CommonInput::new(
            &ciphertext,
            &bad_dlog_commit,
            setup_params.scheme(),
            &pk,
            &g,
        );
        let bad_proof = PiLogProof::prove(
            bad_input,
            ProverSecret::new(&x, &rho),
            &(),
            &mut transcript(),
            &mut rng,
        )?;
        assert!(bad_proof.verify(bad_input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn test_pilof_proof_with_inconsistent_secret_inputs() {
        let _ = pilog_proof_with_inconsistent_secret_inputs::<CurvePoint>();
    }

    fn pilog_proof_with_inconsistent_secret_inputs<C: CurveTrait<Point = C>>() -> Result<()> 
    {
        let mut rng = init_testing();

        // Make a valid secret
        let x = random_plusminus_by_size(&mut rng, ELL);
        let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let pk = decryption_key.encryption_key();
        let g = C::generator();

        // Make a valid common input
        let dlog_commit = g.multiply_by_bignum(&x)?;
        let (ciphertext, rho) = pk.encrypt(&mut rng, &x).unwrap();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let input = CommonInput::<CurvePoint>::new(&ciphertext, &dlog_commit, setup_params.scheme(), &pk, &g);

        // Generate a random plaintext for the secret
        let bad_x = random_plusminus_by_size(&mut rng, ELL);
        let bad_proof_x = PiLogProof::prove(
            input,
            ProverSecret::new(&bad_x, &rho),
            &(),
            &mut transcript(),
            &mut rng,
        )?;

        // The proof should fail to verify
        assert!(bad_proof_x.verify(input, &(), &mut transcript()).is_err());

        // Generate a random rho for the secret
        let bad_rho = Nonce::random(&mut rng, input.prover_encryption_key.modulus());
        let bad_proof_rho = PiLogProof::prove(
            input,
            ProverSecret::new(&x, &bad_rho),
            &(),
            &mut transcript(),
            &mut rng,
        )?;

        // The proof should fail to verify
        assert!(bad_proof_rho.verify(input, &(), &mut transcript()).is_err());

        Ok(())
    }

    #[test]
    fn test_negative_test_swap_proof_elements() {
        negative_test_swap_proof_elements::<CurvePoint>().unwrap();
    }

    fn negative_test_swap_proof_elements<C: CurveTrait<Point = C>>() -> Result<()> {
        let mut rng = init_testing();
        // `rng` will be borrowed. We make another rng to be captured by the closure.
        let mut rng2 = StdRng::from_seed(rng.gen());
        let x = random_plusminus_by_size(&mut rng2, ELL);

        let f = |proof: PiLogProof, input: CommonInput<CurvePoint>| {
            let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;

            // Generate some random elements to use as replacements
            let random_mask = random_plusminus_by_size(&mut rng, ELL + EPSILON);
            let scheme = setup_params.scheme();
            let (bad_plaintext_mask, bad_randomness) = scheme.commit(&random_mask, ELL, &mut rng);

            // Swap mask_commit with a random [`Commitment`]
            let mut bad_proof = proof.clone();
            bad_proof.mask_commit = bad_plaintext_mask.clone();
            assert_ne!(bad_proof.mask_commit, proof.mask_commit);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap plaintext_commit with a random [`Commitment`]
            let mut bad_proof = proof.clone();
            bad_proof.plaintext_commit = bad_plaintext_mask;
            assert_ne!(bad_proof.plaintext_commit, proof.plaintext_commit);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap plaintext_response with a random [`Bignumber`]
            let mut bad_proof = proof.clone();
            assert_ne!(bad_proof.plaintext_response, random_mask);
            bad_proof.plaintext_response = random_mask.clone();
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap challenge with a random [`Bignumber`]
            let mut bad_proof = proof.clone();
            assert_ne!(bad_proof.challenge, random_mask);
            bad_proof.challenge = random_mask;
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap mask_ciphertext with a random [`Ciphertext`]
            let mut bad_proof = proof.clone();
            let plaintext = random_plusminus_by_size(&mut rng, ELL);
            let (ciphertext, _nonce) = input
                .prover_encryption_key
                .encrypt(&mut rng, &plaintext)
                .unwrap();
            bad_proof.mask_ciphertext = ciphertext;
            assert_ne!(bad_proof.mask_ciphertext, proof.mask_ciphertext);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap mask_dlog_commit with a random [`CurvePoint`]
            let mut bad_proof = proof.clone();
            let mask = random_plusminus_by_size(&mut rng, ELL);
            bad_proof.mask_dlog_commit = input.generator.multiply_by_bignum(&mask)?;
            assert_ne!(bad_proof.mask_dlog_commit, proof.mask_dlog_commit);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap nonce_response with a random [`MaskedNonce`]
            let mut bad_proof = proof.clone();
            bad_proof.nonce_response =
                MaskedNonce::random(&mut rng, input.prover_encryption_key.modulus());
            assert_ne!(bad_proof.nonce_response, proof.nonce_response);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap plaintext_commit_response with a random [`MaskedRandomness`]
            let mut bad_proof = proof.clone();
            bad_proof.plaintext_commit_response = bad_randomness.as_masked().to_owned();
            assert_ne!(
                bad_proof.plaintext_commit_response,
                proof.plaintext_commit_response
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            Ok(())
        };

        with_random_paillier_log_proof::<StdRng, C>(&mut rng2, &x, f)?;
        Ok(())
    }

    #[test]
    fn test_pilog_proof_context_must_be_correct() {
        pilog_proof_context_must_be_correct::<CurvePoint>().unwrap();
    }

    fn pilog_proof_context_must_be_correct<C: CurveTrait<Point = C>>() -> Result<()> {
        let mut rng = init_testing();

        let context = BadContext {};
        let x_small = random_plusminus_by_size(&mut rng, ELL);
        let f = |proof: PiLogProof, input: CommonInput<CurvePoint>| {
            let result = proof.verify(input, &context, &mut transcript());
            assert!(result.is_err());
            Ok(())
        };

        with_random_paillier_log_proof::<StdRng, C>(&mut rng, &x_small, f)
    }

    #[test]
    fn test_paillier_log_proof() -> Result<()> {
        let mut rng = init_testing();

        let x_small = random_plusminus_by_size(&mut rng, ELL);
        let x_large =
            random_plusminus_by_size_with_minimum(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;

        // Sampling x in the range 2^ELL should always succeed
        assert!(random_paillier_log_proof_verification::<StdRng, CurvePoint>(&mut rng, &x_small).is_ok());

        // Sampling x in the range (2^{ELL + EPSILON}, 2^{ELL + EPSILON + 1}] should
        // fail
        assert!(random_paillier_log_proof_verification::<StdRng, CurvePoint>(&mut rng, &x_large).is_err());

        Ok(())
    }
}
