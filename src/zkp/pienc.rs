// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof of knowledge that the plaintext of a Pailler ciphertext is
//! in a given range.
//!
//! More precisely, this module includes methods to create and verify a non-interactive
//! zero-knowledge proof of knowledge of the plaintext value of a Paillier ciphertext and that
//! the value is in a desired range.
//! The proof is defined in Figure 14 of CGGMP[^cite].
//!
//! In this application, the acceptable range for the plaintext is fixed according to our
//! [parameters](crate::parameters). The plaintext value must be in the range `[-2^ℓ, 2^ℓ]`,
//! where `ℓ` is [`parameters::ELL`](crate::parameters::ELL).
//!
//! This implementation uses a standard Fiat-Shamir transformation to make the proof
//! non-interactive.
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

/// Proof of knowledge of the plaintext value of a ciphertext, where the value is within a desired
/// range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiEncProof {
    /// Mask for the plaintext value of the ciphertext (`alpha` in the paper).
    plaintext_mask: BigNumber,
    /// Commitment to the plaintext value of the ciphertext (`S` in the paper).
    plaintext_commit: Commitment,
    /// Masking ciphertext (`A` in the paper).
    /// This is the encryption of `plaintext_mask`.
    ciphertext_mask: Ciphertext,
    /// Commitment to the plaintext mask (`C` in the paper).
    plaintext_mask_commit: Commitment,
    /// Fiat-Shamir challenge (`e` in the paper).
    challenge: BigNumber,
    /// Response binding the plaintext value of the ciphertext and its mask (`z1` in the paper).
    plaintext_response: BigNumber,
    /// Response binding the nonce from the original ciphertext and its mask (`z2` in the paper).
    nonce_response: MaskedNonce,
    /// Response binding the commitment randomness used in the two commitments (`z3` in the paper).
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
    /// Generate public input for proving or verifying a [`PiEncProof`] about `ciphertext`.
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

/// The prover's secret knowledge: the in-range plaintext value of the ciphertext and its
/// corresponding nonce.
pub(crate) struct PiEncSecret {
    plaintext: BigNumber,
    nonce: Nonce,
}

impl PiEncSecret {
    /// Collect secret knowledge for proving a `PiEncProof`.
    ///
    /// The `(plaintext, nonce)` tuple here corresponds to the values `(k, rho)` in the paper.
    pub(crate) fn new(plaintext: BigNumber, nonce: Nonce) -> Self {
        Self { plaintext, nonce }
    }
}

impl Proof for PiEncProof {
    type CommonInput = PiEncInput;
    type ProverSecret = PiEncSecret;

    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
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
        let mut transcript = Transcript::new(b"PiEncProof");
        Self::fill_out_transcript(
            &mut transcript,
            input,
            &plaintext_mask,
            &plaintext_commit,
            &ciphertext_mask,
            &plaintext_mask_commit,
        )?;

        // ...and generate a challenge from it (aka `e`)
        let challenge = plusminus_bn_random_from_transcript(&mut transcript, &k256_order());

        // Form proof responses. Each combines one secret value with its mask and the challenge
        // (aka `z1`, `z2`, `z3` respectively)
        let plaintext_response = &plaintext_mask + &challenge * &secret.plaintext;
        let nonce_response = input
            .encryption_key
            .mask(&secret.nonce, &nonce_mask, &challenge);
        let randomness_response = mu.mask(&gamma, &challenge);

        let proof = Self {
            plaintext_mask,
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
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // Check Fiat-Shamir challenge consistency: update the transcript with commitments...
        let mut transcript = Transcript::new(b"PiEncProof");
        Self::fill_out_transcript(
            &mut transcript,
            input,
            &self.plaintext_mask,
            &self.plaintext_commit,
            &self.ciphertext_mask,
            &self.plaintext_mask_commit,
        )?;

        // ...generate a challenge, and make sure it matches the one the prover sent.
        let e = plusminus_bn_random_from_transcript(&mut transcript, &k256_order());
        if e != self.challenge {
            return verify_err!("Fiat-Shamir didn't verify");
        }

        // Check that the plaintext and nonce responses are well-formed (e.g. that the prover did
        // not try to falsify the ciphertext mask)
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

        // Check that the plaintext and commitment randomness responses are well formed (e.g. that
        // the prover did not try to falsify its commitments to the plaintext or plaintext mask)
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
    /// Update the [`Transcript`] with all the commitment values used in the proof.
    fn fill_out_transcript(
        transcript: &mut Transcript,
        input: &PiEncInput,
        plaintext_mask: &BigNumber,
        plaintext_commit: &Commitment,
        ciphertext_mask: &Ciphertext,
        plaintext_mask_commit: &Commitment,
    ) -> Result<()> {
        transcript.append_message(b"PiEnc CommonInput", &serialize!(&input)?);
        transcript.append_message(b"alpha", &plaintext_mask.to_bytes());
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
    use crate::{paillier::DecryptionKey, utils::random_plusminus_by_size_with_minimum};

    fn random_paillier_encryption_in_range_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        plaintext: BigNumber,
    ) -> Result<()> {
        let (decryption_key, _, _) = DecryptionKey::new(rng)?;
        let encryption_key = decryption_key.encryption_key();

        let (ciphertext, nonce) = encryption_key.encrypt(rng, &plaintext)?;
        let setup_params = VerifiedRingPedersen::gen(rng)?;

        let input = PiEncInput {
            setup_params,
            encryption_key,
            ciphertext,
        };

        let proof = PiEncProof::prove(rng, &input, &PiEncSecret { plaintext, nonce })?;

        let proof_bytes = bincode::serialize(&proof).unwrap();
        let roundtrip_proof: PiEncProof = bincode::deserialize(&proof_bytes).unwrap();
        let roundtrip_proof_bytes = bincode::serialize(&roundtrip_proof).unwrap();
        assert_eq!(proof_bytes, roundtrip_proof_bytes);

        proof.verify(&input)
    }

    #[test]
    fn test_paillier_encryption_in_range_proof() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();

        let in_range = random_plusminus_by_size(&mut rng, ELL);
        let too_large =
            random_plusminus_by_size_with_minimum(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;

        // A plaintext in the range 2^ELL should always succeed
        assert!(random_paillier_encryption_in_range_proof(&mut rng, in_range).is_ok());

        // A plaintext that's in range for encryption but larger than 2^ELL should fail
        assert!(random_paillier_encryption_in_range_proof(&mut rng, too_large).is_err());

        Ok(())
    }
}
