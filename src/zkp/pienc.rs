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
//! [EPrint archive, 2021](https://eprint.iacr.org/2021/060.pdf).

use super::Proof;
use crate::{
    errors::*,
    paillier::{Ciphertext, EncryptionKey, MaskedNonce, Nonce},
    parameters::{ELL, EPSILON},
    ring_pedersen::{Commitment, MaskedRandomness, VerifiedRingPedersen},
    utils::{k256_order, plusminus_bn_random_from_transcript, random_plusminus_by_size},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Proof of knowledge of the plaintext value of a ciphertext, where the value
/// is within a desired range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiEncProof {
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
}

/// Common input and setup parameters known to both the prover and verifier.
#[derive(Serialize)]
pub(crate) struct PiEncInput {
    /// The verifier's commitment parameters (`(N^hat, s, t)` in the paper).
    setup_params: VerifiedRingPedersen,
    /// The prover's encryption key (`N_0` in the paper).
    encryption_key: EncryptionKey,
    /// Ciphertext about which we are proving properties (`K` in the paper).
    ciphertext: Ciphertext,
}

impl PiEncInput {
    /// Generate public input for proving or verifying a [`PiEncProof`] about
    /// `ciphertext`.
    pub(crate) fn new(
        verifer_setup_params: VerifiedRingPedersen,
        prover_encryption_key: EncryptionKey,
        ciphertext: Ciphertext,
    ) -> Self {
        Self {
            setup_params: verifer_setup_params,
            encryption_key: prover_encryption_key,
            ciphertext,
        }
    }
}

/// The prover's secret knowledge: the in-range plaintext value of the
/// ciphertext and its corresponding nonce.
pub(crate) struct PiEncSecret {
    plaintext: BigNumber,
    nonce: Nonce,
}

impl PiEncSecret {
    /// Collect secret knowledge for proving a `PiEncProof`.
    ///
    /// The `(plaintext, nonce)` tuple here corresponds to the values `(k, rho)`
    /// in the paper.
    pub(crate) fn new(plaintext: BigNumber, nonce: Nonce) -> Self {
        Self { plaintext, nonce }
    }
}

impl Proof for PiEncProof {
    type CommonInput = PiEncInput;
    type ProverSecret = PiEncSecret;

    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Sample a mask for the plaintext (aka `alpha`)
        let plaintext_mask = random_plusminus_by_size(rng, ELL + EPSILON);

        // Commit to the plaintext (aka `S`)
        let (plaintext_commit, mu) =
            input
                .setup_params
                .scheme()
                .commit(&secret.plaintext, ELL, rng);
        // Encrypt the mask for the plaintext (aka `A, r`)
        let (ciphertext_mask, nonce_mask) = input.encryption_key.encrypt(rng, &plaintext_mask)?;
        // Commit to the mask for the plaintext (aka `C`)
        let (plaintext_mask_commit, gamma) =
            input
                .setup_params
                .scheme()
                .commit(&plaintext_mask, ELL + EPSILON, rng);

        // Fill out the transcript with our fresh commitments...
        Self::fill_out_transcript(
            transcript,
            input,
            &plaintext_commit,
            &ciphertext_mask,
            &plaintext_mask_commit,
        )?;

        // ...and generate a challenge from it (aka `e`)
        let challenge = plusminus_bn_random_from_transcript(transcript, &k256_order());

        // Form proof responses. Each combines one secret value with its mask and the
        // challenge (aka `z1`, `z2`, `z3` respectively)
        let plaintext_response = &plaintext_mask + &challenge * &secret.plaintext;
        let nonce_response = input
            .encryption_key
            .mask(&secret.nonce, &nonce_mask, &challenge);
        let randomness_response = mu.mask(&gamma, &challenge);

        let proof = Self {
            plaintext_commit,
            ciphertext_mask,
            plaintext_mask_commit,
            challenge,
            plaintext_response,
            nonce_response,
            randomness_response,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn verify(&self, input: &Self::CommonInput, transcript: &mut Transcript) -> Result<()> {
        // Check Fiat-Shamir challenge consistency: update the transcript with
        // commitments...
        Self::fill_out_transcript(
            transcript,
            input,
            &self.plaintext_commit,
            &self.ciphertext_mask,
            &self.plaintext_mask_commit,
        )?;

        // ...generate a challenge, and make sure it matches the one the prover sent.
        let e = plusminus_bn_random_from_transcript(transcript, &k256_order());
        if e != self.challenge {
            return verify_err!("Fiat-Shamir didn't verify");
        }

        // Check that the plaintext and nonce responses are well-formed (e.g. that the
        // prover did not try to falsify the ciphertext mask)
        let ciphertext_mask_is_well_formed = {
            let lhs = input
                .encryption_key
                .encrypt_with_nonce(&self.plaintext_response, &self.nonce_response)?;
            let rhs = input.encryption_key.multiply_and_add(
                &e,
                &input.ciphertext,
                &self.ciphertext_mask,
            )?;
            lhs == rhs
        };
        if !ciphertext_mask_is_well_formed {
            return verify_err!("ciphertext mask check (first equality check) failed");
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
            return verify_err!("response validation check (second equality check) failed");
        }

        // Make sure the ciphertext response is in range
        let bound = BigNumber::one() << (ELL + EPSILON);
        if self.plaintext_response < -bound.clone() || self.plaintext_response > bound {
            return verify_err!("bounds check on plaintext response failed");
        }

        Ok(())
    }
}

impl PiEncProof {
    /// Update the [`Transcript`] with all the commitment values used in the
    /// proof.
    fn fill_out_transcript(
        transcript: &mut Transcript,
        input: &PiEncInput,
        plaintext_commit: &Commitment,
        ciphertext_mask: &Ciphertext,
        plaintext_mask_commit: &Commitment,
    ) -> Result<()> {
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
        paillier::DecryptionKey,
        utils::{random_plusminus, random_plusminus_by_size_with_minimum, random_positive_bn},
    };

    fn build_random_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        plaintext: BigNumber,
    ) -> Result<(PiEncProof, PiEncInput)> {
        let (decryption_key, _, _) = DecryptionKey::new(rng)?;
        let encryption_key = decryption_key.encryption_key();

        let (ciphertext, nonce) = encryption_key.encrypt(rng, &plaintext)?;
        let setup_params = VerifiedRingPedersen::gen(rng)?;

        let input = PiEncInput {
            setup_params,
            encryption_key,
            ciphertext,
        };

        let mut transcript = Transcript::new(b"PiEncProof");
        let proof = PiEncProof::prove(
            &input,
            &PiEncSecret { plaintext, nonce },
            &mut transcript,
            rng,
        )?;

        Ok((proof, input))
    }

    #[test]
    fn proof_serializes_correctly() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();

        let plaintext = random_plusminus_by_size(&mut rng, ELL);
        let (proof, input) = build_random_proof(&mut rng, plaintext)?;

        let proof_bytes = bincode::serialize(&proof).unwrap();
        let roundtrip_proof: PiEncProof = bincode::deserialize(&proof_bytes).unwrap();
        let roundtrip_proof_bytes = bincode::serialize(&roundtrip_proof).unwrap();

        assert_eq!(proof_bytes, roundtrip_proof_bytes);
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_ok());
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(roundtrip_proof.verify(&input, &mut transcript).is_ok());

        Ok(())
    }

    #[test]
    fn plaintext_must_be_in_range() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();

        // A plaintext in the range 2^ELL should always succeed
        let in_range = random_plusminus_by_size(&mut rng, ELL);
        let (proof, input) = build_random_proof(&mut rng, in_range)?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_ok());

        // A plaintext in range for encryption but larger (absolute value) than 2^ELL
        // should fail
        let too_large =
            random_plusminus_by_size_with_minimum(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;
        let (proof, input) = build_random_proof(&mut rng, too_large.clone())?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());

        // Ditto with the opposite sign for the too-large plaintext
        let too_small = -too_large;
        let (proof, input) = build_random_proof(&mut rng, too_small)?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());

        // PiEnc expects an input in the range ±2^ELL. The proof can guarantee this
        // range up to the slackness parameter -- that is, that the input is in
        // the range ±2^(ELL + EPSILON) Values in between are only caught
        // sometimes, so they're hard to test.

        // The lower edge case works (2^ELL))
        let lower_bound = BigNumber::one() << ELL;
        let (proof, input) = build_random_proof(&mut rng, lower_bound.clone())?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_ok());
        let (proof, input) = build_random_proof(&mut rng, -lower_bound)?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_ok());

        // The higher edge case fails (2^ELL+EPSILON)
        let upper_bound = BigNumber::one() << (ELL + EPSILON);
        let (proof, input) = build_random_proof(&mut rng, upper_bound.clone())?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());
        let (proof, input) = build_random_proof(&mut rng, -upper_bound)?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());

        Ok(())
    }

    #[test]
    fn every_proof_field_matters() {
        let rng = &mut crate::utils::get_test_rng();
        let plaintext = random_plusminus_by_size(rng, ELL);

        let (proof, input) = build_random_proof(rng, plaintext.clone()).unwrap();

        // Shorthand for input commitment parameters
        let scheme = input.setup_params.scheme();

        // Generate some random elements to use as replacements
        let random_mask = random_plusminus_by_size(rng, ELL + EPSILON);
        let (bad_plaintext_mask, bad_randomness) = scheme.commit(&random_mask, ELL, rng);

        // Bad plaintext commitment (same value, wrong commitment randomness) fails
        {
            let mut bad_proof = proof.clone();
            bad_proof.plaintext_commit = scheme.commit(&plaintext, ELL, rng).0;
            assert_ne!(&bad_proof.plaintext_commit, &proof.plaintext_commit);
            let mut transcript = Transcript::new(b"PiEncProof");
            assert!(bad_proof.verify(&input, &mut transcript).is_err());
        }

        // Bad ciphertext mask (encryption of wrong value with wrong nonce)
        {
            let mut bad_proof = proof.clone();
            bad_proof.ciphertext_mask = input.encryption_key.encrypt(rng, &random_mask).unwrap().0;
            assert_ne!(bad_proof.ciphertext_mask, proof.ciphertext_mask);
            let mut transcript = Transcript::new(b"PiEncProof");
            assert!(bad_proof.verify(&input, &mut transcript).is_err());
        }

        // Bad plaintext mask commitment (commitment to wrong value with wrong
        // randomness) fails
        {
            let mut bad_proof = proof.clone();
            bad_proof.plaintext_mask_commit = bad_plaintext_mask;
            assert_ne!(bad_proof.plaintext_mask_commit, proof.plaintext_mask_commit);
            let mut transcript = Transcript::new(b"PiEncProof");
            assert!(bad_proof.verify(&input, &mut transcript).is_err());
        }

        // Bad challenge fails
        {
            let mut bad_proof = proof.clone();
            bad_proof.challenge = random_plusminus(rng, &k256_order());
            assert_ne!(bad_proof.challenge, proof.challenge);
            let mut transcript = Transcript::new(b"PiEncProof");
            assert!(bad_proof.verify(&input, &mut transcript).is_err());
        }

        // Bad plaintext response fails (this can be an arbitrary integer, using
        // commitment modulus for convenience of generating it)
        {
            let mut bad_proof = proof.clone();
            bad_proof.plaintext_response = random_positive_bn(rng, scheme.modulus());
            assert_ne!(bad_proof.plaintext_response, proof.plaintext_response);
            let mut transcript = Transcript::new(b"PiEncProof");
            assert!(bad_proof.verify(&input, &mut transcript).is_err());
        }

        // Bad nonce response fails
        {
            let mut bad_proof = proof.clone();
            bad_proof.nonce_response = MaskedNonce::random(rng, input.encryption_key.modulus());
            assert_ne!(bad_proof.nonce_response, proof.nonce_response);
            let mut transcript = Transcript::new(b"PiEncProof");
            assert!(bad_proof.verify(&input, &mut transcript).is_err());
        }

        // Bad randomness response fails (ditto on arbitrary integer)
        {
            let mut bad_proof = proof.clone();
            bad_proof.randomness_response = bad_randomness.as_masked().to_owned();
            assert_ne!(bad_proof.randomness_response, proof.randomness_response);
            let mut transcript = Transcript::new(b"PiEncProof");
            assert!(bad_proof.verify(&input, &mut transcript).is_err());
        }

        // The original proof itself verifies correctly, though!
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_ok());
    }

    #[test]
    fn proof_must_be_constructed_with_knowledge_of_secrets() -> Result<()> {
        let rng = &mut crate::utils::get_test_rng();

        // Form common inputs
        let (decryption_key, _, _) = DecryptionKey::new(rng)?;
        let encryption_key = decryption_key.encryption_key();

        // Form secret input
        let plaintext = random_plusminus_by_size(rng, ELL);
        let (ciphertext, nonce) = encryption_key.encrypt(rng, &plaintext)?;
        let setup_params = VerifiedRingPedersen::extract(&decryption_key, rng)?;

        let input = PiEncInput {
            setup_params,
            encryption_key: encryption_key.clone(),
            ciphertext,
        };

        // Correctly formed proof verifies correctly
        let mut transcript = Transcript::new(b"PiEncProof");
        let proof = PiEncProof::prove(
            &input,
            &PiEncSecret {
                plaintext: plaintext.clone(),
                nonce: nonce.clone(),
            },
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_ok());

        // Forming with the wrong plaintext fails
        let wrong_plaintext = random_plusminus_by_size(rng, ELL);
        assert_ne!(wrong_plaintext, plaintext);
        let mut transcript = Transcript::new(b"PiEncProof");
        let proof = PiEncProof::prove(
            &input,
            &PiEncSecret {
                plaintext: wrong_plaintext,
                nonce: nonce.clone(),
            },
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());

        // Forming with the wrong nonce fails
        let (_, wrong_nonce) = encryption_key.encrypt(rng, &plaintext)?;
        assert_ne!(wrong_nonce, nonce);
        let mut transcript = Transcript::new(b"PiEncProof");
        let proof = PiEncProof::prove(
            &input,
            &PiEncSecret {
                plaintext,
                nonce: wrong_nonce,
            },
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());

        Ok(())
    }

    #[test]
    fn verification_requires_correct_common_input() -> Result<()> {
        // Replace each field of `CommonInput` with something else to verify
        let mut rng = crate::utils::get_test_rng();

        // Form inputs
        let plaintext = random_plusminus_by_size(&mut rng, ELL);
        let (proof, mut input) = build_random_proof(&mut rng, plaintext.clone())?;

        // Verification works on the original input
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_ok());

        // Verification fails with the wrong setup params
        let (bad_decryption_key, _, _) = DecryptionKey::new(&mut rng)?;
        let bad_setup_params = VerifiedRingPedersen::extract(&bad_decryption_key, &mut rng)?;
        let setup_params = input.setup_params;
        input.setup_params = bad_setup_params;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());
        input.setup_params = setup_params;

        // Verification fails with the wrong encryption key
        let bad_encryption_key = DecryptionKey::new(&mut rng)?.0.encryption_key();
        let encryption_key = input.encryption_key;
        input.encryption_key = bad_encryption_key;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());
        input.encryption_key = encryption_key;

        // Verification fails with the wrong ciphertext
        let (bad_ciphertext, _) = input.encryption_key.encrypt(&mut rng, &plaintext)?;
        let ciphertext = input.ciphertext;
        input.ciphertext = bad_ciphertext;
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_err());
        input.ciphertext = ciphertext;

        // Proof still works (as in, it wasn't just failing due to bad transcripts)
        let mut transcript = Transcript::new(b"PiEncProof");
        assert!(proof.verify(&input, &mut transcript).is_ok());

        Ok(())
    }
}
