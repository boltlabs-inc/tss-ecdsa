// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof of knowledge that the plaintext of a
//! Pailler ciphertext is in a given range.
//!
//! More precisely, this module includes methods to create and verify a
//! non-interactive zero-knowledge proof of knowledge of the plaintext value of
//! a Paillier ciphertext and that the value is in a desired range.
//! The proof is defined in Figure 14 of CGGMP[^cite].
//!
//! In this application, the acceptable range for the plaintext is fixed
//! according to our [parameters](crate::parameters). The plaintext value must
//! be in the range `[-2^ℓ, 2^ℓ]`, where `ℓ` is
//! [`parameters::ELL`](crate::parameters::ELL).
//!
//! This implementation uses a standard Fiat-Shamir transformation to make the
//! proof non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! [EPrint archive, 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf).
use crate::{
    curve::CurveTrait,
    errors::*,
    paillier::{Ciphertext, EncryptionKey, MaskedNonce, Nonce},
    parameters::{ELL, EPSILON},
    ring_pedersen::{Commitment, MaskedRandomness, VerifiedRingPedersen},
    utils::{plusminus_challenge_from_transcript, random_plusminus_by_size},
    zkp::{Proof, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;

/// Proof of knowledge of the plaintext value of a ciphertext, where the value
/// is within a desired range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiEncProof<C: CurveTrait> {
    /// Commitment to the plaintext value of the ciphertext (`S` in the paper).
    plaintext_commit: Commitment,
    /// Masking ciphertext (`A` in the paper).
    /// This is the encryption of `plaintext_mask`.
    ciphertext_mask: Ciphertext,
    /// Commitment to the plaintext mask (`C` in the paper).
    plaintext_mask_commit: Commitment,
    /// Fiat-Shamir challenge (`e` in the paper).
    challenge: BigNumber,
    /// Response binding the plaintext value of the ciphertext and its mask
    /// (`z1` in the paper).
    plaintext_response: BigNumber,
    /// Response binding the nonce from the original ciphertext and its mask
    /// (`z2` in the paper).
    nonce_response: MaskedNonce,
    /// Response binding the commitment randomness used in the two commitments
    /// (`z3` in the paper).
    randomness_response: MaskedRandomness,
    /// Phantom data to tie the proof to the curve type.
    curve: std::marker::PhantomData<C>,
}

/// Common input and setup parameters known to both the prover and verifier.
///
/// Copying/Cloning references is harmless and sometimes necessary. So we
/// implement Clone and Copy for this type.
#[derive(Serialize, Copy, Clone)]
pub(crate) struct PiEncInput<'a> {
    /// The verifier's commitment parameters (`(N^hat, s, t)` in the paper).
    setup_params: &'a VerifiedRingPedersen,
    /// The prover's encryption key (`N_0` in the paper).
    encryption_key: &'a EncryptionKey,
    /// Ciphertext about which we are proving properties (`K` in the paper).
    ciphertext: &'a Ciphertext,
}

impl<'a> PiEncInput<'a> {
    /// Generate public input for proving or verifying a [`PiEncProof`] about
    /// `ciphertext`.
    pub(crate) fn new(
        verifer_setup_params: &'a VerifiedRingPedersen,
        prover_encryption_key: &'a EncryptionKey,
        ciphertext: &'a Ciphertext,
    ) -> PiEncInput<'a> {
        Self {
            setup_params: verifer_setup_params,
            encryption_key: prover_encryption_key,
            ciphertext,
        }
    }
}

/// The prover's secret knowledge: the in-range plaintext value of the
/// ciphertext and its corresponding nonce.
///
/// Copying/Cloning references is harmless and sometimes necessary. So we
/// implement Clone and Copy for this type.
#[derive(Copy, Clone)]
pub(crate) struct PiEncSecret<'a> {
    plaintext: &'a BigNumber,
    nonce: &'a Nonce,
}

impl Debug for PiEncSecret<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("pienc::Secret")
            .field("plaintext", &"[redacted]")
            .field("nonce", &"[redacted]")
            .finish()
    }
}

impl<'a> PiEncSecret<'a> {
    /// Collect secret knowledge for proving a `PiEncProof`.
    ///
    /// The `(plaintext, nonce)` tuple here corresponds to the values `(k, rho)`
    /// in the paper.
    pub(crate) fn new(plaintext: &'a BigNumber, nonce: &'a Nonce) -> PiEncSecret<'a> {
        Self { plaintext, nonce }
    }
}

impl<C: CurveTrait> Proof for PiEncProof<C> {
    type CommonInput<'a> = PiEncInput<'a>;
    type ProverSecret<'b> = PiEncSecret<'b>;
    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: Self::CommonInput<'_>,
        secret: Self::ProverSecret<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Sample a mask for the plaintext (aka `alpha`)
        let plaintext_mask = random_plusminus_by_size(rng, ELL + EPSILON);

        // Commit to the plaintext (aka `S`)
        let (plaintext_commit, mu) = input
            .setup_params
            .scheme()
            .commit(secret.plaintext, ELL, rng);
        // Encrypt the mask for the plaintext (aka `A, r`)
        let (ciphertext_mask, nonce_mask) = input
            .encryption_key
            .encrypt(rng, &plaintext_mask)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        // Commit to the mask for the plaintext (aka `C`)
        let (plaintext_mask_commit, gamma) =
            input
                .setup_params
                .scheme()
                .commit(&plaintext_mask, ELL + EPSILON, rng);

        // Fill out the transcript with our fresh commitments...
        Self::fill_transcript(
            transcript,
            context,
            &input,
            &plaintext_commit,
            &ciphertext_mask,
            &plaintext_mask_commit,
        )?;

        // ...and generate a challenge from it (aka `e`)
        let challenge = plusminus_challenge_from_transcript::<C>(transcript)?;

        // Form proof responses. Each combines one secret value with its mask and the
        // challenge (aka `z1`, `z2`, `z3` respectively)
        let plaintext_response = &plaintext_mask + &challenge * secret.plaintext;
        let nonce_response = input
            .encryption_key
            .mask(secret.nonce, &nonce_mask, &challenge);
        let randomness_response = mu.mask(&gamma, &challenge);

        let proof = Self {
            plaintext_commit,
            ciphertext_mask,
            plaintext_mask_commit,
            challenge,
            plaintext_response,
            nonce_response,
            randomness_response,
            curve: std::marker::PhantomData,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn verify(
        self,
        input: Self::CommonInput<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        // Check Fiat-Shamir challenge consistency: update the transcript with
        // commitments...
        Self::fill_transcript(
            transcript,
            context,
            &input,
            &self.plaintext_commit,
            &self.ciphertext_mask,
            &self.plaintext_mask_commit,
        )?;

        // ...generate a challenge, and make sure it matches the one the prover sent.
        let e = plusminus_challenge_from_transcript::<C>(transcript)?;
        if e != self.challenge {
            error!("Fiat-Shamir didn't verify");
            return Err(InternalError::ProtocolError(None));
        }

        // Check that the plaintext and nonce responses are well-formed (e.g. that the
        // prover did not try to falsify the ciphertext mask)
        let ciphertext_mask_is_well_formed = {
            let lhs = input
                .encryption_key
                .encrypt_with_nonce(&self.plaintext_response, &self.nonce_response)
                .map_err(|_| InternalError::ProtocolError(None))?;
            let rhs = input
                .encryption_key
                .multiply_and_add(&e, input.ciphertext, &self.ciphertext_mask)
                .map_err(|_| InternalError::ProtocolError(None))?;
            lhs == rhs
        };
        if !ciphertext_mask_is_well_formed {
            error!("ciphertext mask check (first equality check) failed");
            return Err(InternalError::ProtocolError(None));
        }

        // Check that the plaintext and commitment randomness responses are well formed
        // (e.g. that the prover did not try to falsify its commitments to the
        // plaintext or plaintext mask)
        let responses_match_commitments = {
            let lhs = input
                .setup_params
                .scheme()
                .reconstruct(&self.plaintext_response, &self.randomness_response);
            let rhs = input.setup_params.scheme().combine(
                &self.plaintext_mask_commit,
                &self.plaintext_commit,
                &e,
            );
            lhs == rhs
        };
        if !responses_match_commitments {
            error!("response validation check (second equality check) failed");
            return Err(InternalError::ProtocolError(None));
        }

        // Make sure the ciphertext response is in range
        let bound = BigNumber::one() << (ELL + EPSILON);
        if self.plaintext_response < -bound.clone() || self.plaintext_response > bound {
            error!("bounds check on plaintext response failed");
            return Err(InternalError::ProtocolError(None));
        }

        Ok(())
    }
}

impl<C: CurveTrait> PiEncProof<C> {
    /// Update the [`Transcript`] with all the commitment values used in the
    /// proof.
    fn fill_transcript(
        transcript: &mut Transcript,
        context: &impl ProofContext,
        input: &PiEncInput,
        plaintext_commit: &Commitment,
        ciphertext_mask: &Ciphertext,
        plaintext_mask_commit: &Commitment,
    ) -> Result<()> {
        transcript.append_message(b"PiEnc Context", &context.as_bytes()?);
        transcript.append_message(b"PiEnc CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, A, C)",
            &[
                plaintext_commit.to_bytes(),
                ciphertext_mask.to_bytes(),
                plaintext_mask_commit.to_bytes(),
            ]
            .concat(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::{CurveTrait, TestCurve},
        paillier::DecryptionKey,
        utils::{
            random_plusminus, random_plusminus_by_size_with_minimum, random_positive_bn,
            testing::init_testing,
        },
        zkp::BadContext,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn transcript() -> Transcript {
        Transcript::new(b"PiEncProof")
    }

    // Shorthand to avoid putting types for closure arguments.
    // Note: This does not work on closures that capture variables.
    type ProofTest = fn(PiEncProof<TestCurve>, PiEncInput) -> Result<()>;

    /// Generate a [`PiEncProof`] and [`PiEncInput`] and pass them to the
    /// `test_code` closure.
    fn with_random_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        plaintext: BigNumber,
        mut test_code: impl FnMut(PiEncProof<TestCurve>, PiEncInput) -> Result<()>,
    ) -> Result<()> {
        let (decryption_key, _, _) = DecryptionKey::new(rng).unwrap();
        let encryption_key = decryption_key.encryption_key();

        let (ciphertext, nonce) = encryption_key.encrypt(rng, &plaintext).unwrap();
        let setup_params = VerifiedRingPedersen::gen(rng, &())?;

        let input = PiEncInput::new(&setup_params, &encryption_key, &ciphertext);
        let proof = PiEncProof::prove(
            input,
            PiEncSecret::new(&plaintext, &nonce),
            &(),
            &mut transcript(),
            rng,
        )?;
        test_code(proof, input)
    }

    #[test]
    fn pienc_proof_context_must_be_correct() -> Result<()> {
        let mut rng = init_testing();

        let plaintext = random_plusminus_by_size(&mut rng, ELL);

        let f: ProofTest = |proof, input| {
            let context = BadContext {};
            let result = proof.verify(input, &context, &mut transcript());
            assert!(result.is_err());
            Ok(())
        };
        with_random_proof(&mut rng, plaintext, f).unwrap();

        Ok(())
    }

    #[test]
    fn proof_serializes_correctly() -> Result<()> {
        let mut rng = init_testing();
        let plaintext = random_plusminus_by_size(&mut rng, ELL);

        let f: ProofTest = |proof, input| {
            let proof_bytes = bincode::serialize(&proof).unwrap();
            let roundtrip_proof: PiEncProof<TestCurve> =
                bincode::deserialize(&proof_bytes).unwrap();
            let roundtrip_proof_bytes = bincode::serialize(&roundtrip_proof).unwrap();

            assert_eq!(proof_bytes, roundtrip_proof_bytes);
            assert!(proof.verify(input, &(), &mut transcript()).is_ok());
            assert!(roundtrip_proof
                .verify(input, &(), &mut transcript())
                .is_ok());
            Ok(())
        };
        with_random_proof(&mut rng, plaintext, f)?;
        Ok(())
    }

    #[test]
    fn plaintext_must_be_in_range() -> Result<()> {
        let mut rng = init_testing();
        // `rng` will be borrowed. We make another rng to be captured by the closure.
        let mut rng2 = StdRng::from_seed(rng.gen());

        let test_code_is_ok: ProofTest = |proof, input| {
            assert!(proof.verify(input, &(), &mut transcript()).is_ok());
            Ok(())
        };

        let test_code_is_err: ProofTest = |proof, input| {
            assert!(proof.verify(input, &(), &mut transcript()).is_err());
            Ok(())
        };

        // A plaintext in the range 2^ELL should always succeed
        let in_range = random_plusminus_by_size(&mut rng, ELL);
        with_random_proof(&mut rng, in_range, test_code_is_ok)?;

        // A plaintext in range for encryption but larger (absolute value) than 2^ELL
        // should fail
        let too_large =
            random_plusminus_by_size_with_minimum(&mut rng2, ELL + EPSILON + 1, ELL + EPSILON)?;

        with_random_proof(&mut rng2, too_large.clone(), test_code_is_err)?;

        // Ditto with the opposite sign for the too-large plaintext
        let too_small = -too_large;
        with_random_proof(&mut rng2, too_small, test_code_is_err)?;

        // PiEnc expects an input in the range ±2^ELL. The proof can guarantee this
        // range up to the slackness parameter -- that is, that the input is in
        // the range ±2^(ELL + EPSILON) Values in between are only caught
        // sometimes, so they're hard to test.

        // The lower edge case works (2^ELL))
        let lower_bound = BigNumber::one() << ELL;
        with_random_proof(&mut rng2, lower_bound.clone(), test_code_is_ok)?;

        with_random_proof(&mut rng2, -lower_bound, test_code_is_ok)?;

        // The higher edge case fails (2^ELL+EPSILON)
        let upper_bound = BigNumber::one() << (ELL + EPSILON);
        with_random_proof(&mut rng2, upper_bound.clone(), test_code_is_err)?;

        with_random_proof(&mut rng2, -upper_bound, test_code_is_err)?;
        Ok(())
    }

    #[test]
    fn every_proof_field_matters() {
        let rng = &mut init_testing();
        let plaintext = random_plusminus_by_size(rng, ELL);
        // `rng` will be borrowed. We make another rng to be captured by the closure.
        let rng2 = &mut StdRng::from_seed(rng.gen());

        let f = |proof: PiEncProof<TestCurve>, input: PiEncInput| {
            // Shorthand for input commitment parameters
            let scheme = input.setup_params.scheme();

            // Generate some random elements to use as replacements
            let random_mask = random_plusminus_by_size(rng2, ELL + EPSILON);
            let (bad_plaintext_mask, bad_randomness) = scheme.commit(&random_mask, ELL, rng2);

            // Bad plaintext commitment (same value, wrong commitment randomness) fails
            {
                let mut bad_proof = proof.clone();
                bad_proof.plaintext_commit = scheme.commit(&plaintext, ELL, rng2).0;
                assert_ne!(&bad_proof.plaintext_commit, &proof.plaintext_commit);
                assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            }

            // Bad ciphertext mask (encryption of wrong value with wrong nonce)
            {
                let mut bad_proof = proof.clone();
                bad_proof.ciphertext_mask =
                    input.encryption_key.encrypt(rng2, &random_mask).unwrap().0;
                assert_ne!(bad_proof.ciphertext_mask, proof.ciphertext_mask);
                assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            }

            // Bad plaintext mask commitment (commitment to wrong value with wrong
            // randomness) fails
            {
                let mut bad_proof = proof.clone();
                bad_proof.plaintext_mask_commit = bad_plaintext_mask;
                assert_ne!(bad_proof.plaintext_mask_commit, proof.plaintext_mask_commit);
                assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            }

            // Bad challenge fails
            {
                let mut bad_proof = proof.clone();
                bad_proof.challenge = random_plusminus(rng2, &TestCurve::order());
                assert_ne!(bad_proof.challenge, proof.challenge);
                assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            }

            // Bad plaintext response fails (this can be an arbitrary integer, using
            // commitment modulus for convenience of generating it)
            {
                let mut bad_proof = proof.clone();
                bad_proof.plaintext_response = random_positive_bn(rng2, scheme.modulus());
                assert_ne!(bad_proof.plaintext_response, proof.plaintext_response);
                assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            }

            // Bad nonce response fails
            {
                let mut bad_proof = proof.clone();
                bad_proof.nonce_response =
                    MaskedNonce::random(rng2, input.encryption_key.modulus());
                assert_ne!(bad_proof.nonce_response, proof.nonce_response);
                assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            }

            // Bad randomness response fails (ditto on arbitrary integer)
            {
                let mut bad_proof = proof.clone();
                bad_proof.randomness_response = bad_randomness.as_masked().to_owned();
                assert_ne!(bad_proof.randomness_response, proof.randomness_response);
                assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            }

            // The original proof itself verifies correctly, though!
            assert!(proof.verify(input, &(), &mut transcript()).is_ok());
            Ok(())
        };

        with_random_proof(rng, plaintext.clone(), f).unwrap();
    }

    #[test]
    fn proof_must_be_constructed_with_knowledge_of_secrets() -> Result<()> {
        let rng = &mut init_testing();

        // Form common inputs
        let (decryption_key, _, _) = DecryptionKey::new(rng).unwrap();
        let encryption_key = decryption_key.encryption_key();

        // Form secret input
        let plaintext = random_plusminus_by_size(rng, ELL);
        let (ciphertext, nonce) = encryption_key.encrypt(rng, &plaintext).unwrap();
        let setup_params = VerifiedRingPedersen::extract(&decryption_key, &(), rng)?;

        let input = PiEncInput::new(&setup_params, &encryption_key, &ciphertext);

        // Correctly formed proof verifies correctly
        let proof: PiEncProof<TestCurve> = PiEncProof::prove(
            input,
            PiEncSecret::new(&plaintext, &nonce),
            &(),
            &mut transcript(),
            rng,
        )?;
        assert!(proof.verify(input, &(), &mut transcript()).is_ok());

        // Forming with the wrong plaintext fails
        let wrong_plaintext = random_plusminus_by_size(rng, ELL);
        assert_ne!(wrong_plaintext, plaintext);
        let proof: PiEncProof<TestCurve> = PiEncProof::prove(
            input,
            PiEncSecret::new(&wrong_plaintext, &nonce),
            &(),
            &mut transcript(),
            rng,
        )?;
        assert!(proof.verify(input, &(), &mut transcript()).is_err());

        // Forming with the wrong nonce fails
        let (_, wrong_nonce) = encryption_key.encrypt(rng, &plaintext).unwrap();
        assert_ne!(wrong_nonce, nonce);
        let proof: PiEncProof<TestCurve> = PiEncProof::prove(
            input,
            PiEncSecret::new(&wrong_plaintext, &wrong_nonce),
            &(),
            &mut transcript(),
            rng,
        )?;
        assert!(proof.verify(input, &(), &mut transcript()).is_err());

        Ok(())
    }

    #[test]
    fn verification_requires_correct_common_input() -> Result<()> {
        // Replace each field of `CommonInput` with something else to verify
        let mut rng = init_testing();
        // `rng` will be borrowed. We make another rng to be captured by the closure.
        let rng2 = &mut StdRng::from_seed(rng.gen());
        let plaintext = random_plusminus_by_size(&mut rng, ELL);

        let verify_tests = |proof: PiEncProof<TestCurve>, input: PiEncInput| {
            // Verification works on the original input
            assert!(proof.clone().verify(input, &(), &mut transcript()).is_ok());

            // Verification fails with the wrong setup params
            let (bad_decryption_key, _, _) = DecryptionKey::new(rng2).unwrap();
            let bad_setup_params = VerifiedRingPedersen::extract(&bad_decryption_key, &(), rng2)?;
            let new_input =
                PiEncInput::new(&bad_setup_params, input.encryption_key, input.ciphertext);
            assert!(proof
                .clone()
                .verify(new_input, &(), &mut transcript())
                .is_err());

            // Verification fails with the wrong encryption key
            let bad_encryption_key = DecryptionKey::new(rng2).unwrap().0.encryption_key();
            let new_input =
                PiEncInput::new(input.setup_params, &bad_encryption_key, input.ciphertext);
            assert!(proof
                .clone()
                .verify(new_input, &(), &mut transcript())
                .is_err());

            // Verification fails with the wrong ciphertext
            let (bad_ciphertext, _) = input.encryption_key.encrypt(rng2, &plaintext).unwrap();
            let new_input =
                PiEncInput::new(input.setup_params, input.encryption_key, &bad_ciphertext);
            assert!(proof
                .clone()
                .verify(new_input, &(), &mut transcript())
                .is_err());

            // Proof still works (as in, it wasn't just failing due to bad transcripts)
            assert!(proof.verify(input, &(), &mut transcript()).is_ok());
            Ok(())
        };

        // Form inputs
        with_random_proof(&mut rng, plaintext.clone(), verify_tests)?;
        Ok(())
    }
}
