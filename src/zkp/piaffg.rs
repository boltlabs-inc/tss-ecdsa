// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof of knowledge that a Paillier ciphertext
//! was the result of an affine-like transformation.
//!
//! In more detail, this module includes types for creating and verifying a
//! non-interactive zero-knowledge proof of knowledge of the following: The
//! prover knows private values `x ∈ ±2^ℓ` and `y ∈ ±2^ℓ` such that (1) public
//! value `X = g^x`, (2) public Paillier ciphertext `Y = Enc(pk0, y)`, and (3)
//! public parameters `C` and `D` are such that `D = C^x Enc(pk1, y)` where
//! `pk0` and `pk1` are public Paillier encryption keys. The proof is defined in
//! Figure 15 of CGGMP[^cite].
//!
//! This implementation uses a standard Fiat-Shamir transformation to make the
//! proof non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/2021/060.pdf).

use crate::{
    errors::*,
    paillier::{Ciphertext, EncryptionKey, MaskedNonce, Nonce},
    parameters::{ELL, ELL_PRIME, EPSILON},
    ring_pedersen::{Commitment, MaskedRandomness, VerifiedRingPedersen},
    utils::{
        self, k256_order, plusminus_bn_random_from_transcript, random_plusminus_by_size,
        within_bound_by_size,
    },
    zkp::{Proof, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::warn;
use utils::CurvePoint;
use zeroize::ZeroizeOnDrop;

/// Proof of knowledge that a Paillier ciphertext was the result of an
/// affine-line transformation and the plaintext falls within an appropriate
/// range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiAffgProof {
    /// A random multiplicative coefficient (`ɑ` in the paper).
    random_mult_coeff: BigNumber,
    /// A random additive coefficient (`β` in the paper).
    random_add_coeff: BigNumber,
    /// A commitment to the multiplicative coefficient (`S` in the paper).
    mult_coeff_commit: Commitment,
    /// A commitment to the additive coefficient (`T` in the paper).
    add_coeff_commit: Commitment,
    /// A ciphertext produced by the affine-like transformation applied to the
    /// random multiplicative and random additive coefficients (`A` in the
    /// paper).
    random_affine_ciphertext: Ciphertext,
    /// A group exponentiation of the random multiplicative coefficient (`B_x`
    /// in the paper).
    random_mult_coeff_exp: CurvePoint,
    /// A Paillier ciphertext, under the 1st encryption key, of the random
    /// additive coefficient (`B_y` in the paper).
    random_add_coeff_ciphertext_1: Ciphertext,
    /// A ring-Pedersen commitment to the random multiplicative coefficient (`E`
    /// in the paper).
    random_mult_coeff_commit: Commitment,
    /// A ring-Pedersen commitment to the random additive coefficient (`F` in
    /// the paper).
    random_add_coeff_commit: Commitment,
    /// The Fiat-Shamir challenge value (`e` in the paper).
    challenge: BigNumber,
    /// A mask of the (secret) multiplicative coefficient (`z_1` in the paper).
    masked_mult_coeff: BigNumber,
    /// A mask of the (secret) additive coefficient (`z_2` in the paper).
    masked_add_coeff: BigNumber,
    /// A mask of the commitment randomness of the (secret) multiplicative
    /// coefficient (`z_3` in the paper).
    masked_mult_coeff_commit_randomness: MaskedRandomness,
    /// A mask of the commitment randomness of the (secret) additive coefficient
    /// (`z_4` in the paper).
    masked_add_coeff_commit_randomness: MaskedRandomness,
    /// A mask of the Paillier ciphertext nonce of the (secret) additive
    /// coefficient under the 0th encryption key (`w` in the paper).
    masked_add_coeff_nonce_0: MaskedNonce,
    /// A mask of the Paillier ciphertext nonce of the (secret) additive
    /// coefficient under the 1st encryption key (`w_y` in the paper).
    masked_add_coeff_nonce_1: MaskedNonce,
}

/// Common input and setup parameters for [`PiAffgProof`] known to both the
/// prover and verifier.
#[derive(Serialize)]
pub(crate) struct PiAffgInput {
    /// The verifier's commitment parameters (`(Nhat, s, t)` in the paper).
    verifier_setup_params: VerifiedRingPedersen,
    /// First Paillier encryption key (`N_0` in the paper).
    encryption_key_0: EncryptionKey,
    /// Second Paillier encryption key (`N_1` in the paper).
    encryption_key_1: EncryptionKey,
    /// Input Paillier ciphertext (`C` in the paper).
    input_ciphertext: Ciphertext,
    /// Output Paillier ciphertext (`D` in the paper).
    output_ciphertext: Ciphertext,
    /// Paillier ciphertext of the prover's additive coefficient (`Y` in the
    /// paper).
    additive_coefficient_ciphertext: Ciphertext,
    /// Exponentiation of the prover's multiplicative coefficient (`X` in the
    /// paper).
    multiplicative_coefficient_exponentiation: CurvePoint,
}

impl PiAffgInput {
    /// Construct a new [`PiAffgInput`] type.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        verifier_setup_params: VerifiedRingPedersen,
        encryption_key_0: EncryptionKey,
        encryption_key_1: EncryptionKey,
        exponentiation: Ciphertext,
        affine_output: Ciphertext,
        ciphertext: Ciphertext,
        paillier_exponentiation: CurvePoint,
    ) -> Self {
        Self {
            verifier_setup_params,
            encryption_key_0,
            encryption_key_1,
            input_ciphertext: exponentiation,
            output_ciphertext: affine_output,
            additive_coefficient_ciphertext: ciphertext,
            multiplicative_coefficient_exponentiation: paillier_exponentiation,
        }
    }
}

/// The prover's secret knowledge.
#[derive(ZeroizeOnDrop)]
pub(crate) struct PiAffgSecret {
    /// The multiplicative coefficient (`x` in the paper).
    mult_coeff: BigNumber,
    /// The additive coefficient (`y` in the paper).
    add_coeff: BigNumber,
    /// The additive coefficient's nonce produced when encrypting using the 0th
    /// encryption key (`ρ` in the paper).
    add_coeff_nonce_0: Nonce,
    /// The additive coefficient's nonce produced when encrypting using the 1st
    /// encryption key (`ρ_y` in the paper).
    add_coeff_nonce_1: Nonce,
}

impl Debug for PiAffgSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("piaffg::Secret")
            .field("x", &"[redacted]")
            .field("y", &"[redacted]")
            .field("rho", &"[redacted]")
            .field("rho_y", &"[redacted]")
            .finish()
    }
}

impl PiAffgSecret {
    /// Construct a new [`PiAffgSecret`] type.
    pub(crate) fn new(
        group_element: BigNumber,
        plaintext: BigNumber,
        group_element_nonce: Nonce,
        plaintext_nonce: Nonce,
    ) -> Self {
        Self {
            mult_coeff: group_element,
            add_coeff: plaintext,
            add_coeff_nonce_0: group_element_nonce,
            add_coeff_nonce_1: plaintext_nonce,
        }
    }
}

impl Proof for PiAffgProof {
    type CommonInput = PiAffgInput;
    type ProverSecret = PiAffgSecret;

    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    #[allow(clippy::many_single_char_names)]
    fn prove<R: RngCore + CryptoRng>(
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // The proof works as follows.
        //
        // Recall that the prover wants to prove that some transformations on
        // some public values encodes an affine-like transformation on the
        // prover's secret values. In more detail, the prover has two main
        // secret inputs:
        //
        // - `x`, which encodes the "multiplicative coefficient", and
        // - `y`, which encodes the "additive coefficient".
        //
        // The prover wants to prove that (1) operations on some public
        // ciphertext values equates to computing `z · x + y`, where `z` is some
        // value given as part of the public input, (2) some of these
        // ciphertexts match ciphertexts encoded under a different key, and (3)
        // `x` and `y` fall within acceptable ranges.
        //
        // In even more detail (all variable names refer to those used in the
        // paper), let `C_i[·]` notation denote the resulting ciphertext using
        // the `i`th encryption key. The prover wants to prove the following
        // three claims:
        //
        // 1. `C_0[z] ^ x · C_0[y] = D`, where `C_0[z]` and `D` are public
        // values.
        //
        // 2. `C_1[y] = Y`, where `Y` is a public value.
        //
        // 3. `g ^ x = X`, where `X` is a public value.
        //
        // This is done as follows. First, the prover constructs such a
        // computation on _random_ values `ɑ` and `β` by computing `A = C_0[z] ^
        // ɑ · C_0[β]`. Likewise, it produces "encoded" version of these random
        // values `B_x = g ^ ɑ` and `B_y = C_1[β]`. It then demonstrates
        // equality of the following three conditions, using a challenge value
        // `e` produced by using Fiat-Shamir:
        //
        // 1. C_0[z] ^ (ɑ + e x) · C_0[β + e y] = A * D ^ e (note that if `D`
        //    "encodes" `z x + y` this check will pass)
        //
        // 2. g ^ (ɑ + e x) = B_x · X ^ e (note that if `X = g ^ x` this check
        //    will pass)
        //
        // 3. C_1[β + e y] = B_y · Y ^ e (note that if `Y = C_1[y]` this check
        //    will pass)
        //
        // This checks the main properties we are going for, however it doesn't
        // enforce yet that `ɑ + e x`, `β + e y`, etc. were computed correctly.
        // This is handled by using ring-Pedersen commitments.
        //
        // Finally, we do a range check on `x` and `y` by checking that `ɑ + e
        // x` and `β + e y` fall within the acceptable ranges.

        // Sample a random multiplicative coefficient from `±2^{ℓ+ε}` (`ɑ` in the
        // paper).
        let random_mult_coeff = random_plusminus_by_size(rng, ELL + EPSILON);
        // Sample a random additive coefficient from `±2^{ℓ'+ε}` (`β` in the paper).
        let random_add_coeff = random_plusminus_by_size(rng, ELL_PRIME + EPSILON);
        // Encrypt the random additive coefficient using the 0th encryption key.
        let (random_additive_coeff_ciphertext_0, random_add_coeff_nonce_0) = input
            .encryption_key_0
            .encrypt(rng, &random_add_coeff)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        // Compute the affine-like operation on our random coefficients and the
        // input ciphertext using the 0th encryption key (producing `A` in the paper).
        let random_affine_ciphertext = input
            .encryption_key_0
            .multiply_and_add(
                &random_mult_coeff,
                &input.input_ciphertext,
                &random_additive_coeff_ciphertext_0,
            )
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        // Compute the exponentiation of the multiplicative coefficient
        // (producing `B_x` in the paper)
        let random_mult_coeff_exp = CurvePoint::GENERATOR.multiply_by_scalar(&random_mult_coeff)?;
        // Encrypt the random additive coefficient using the 1st encryption key
        // (producing `B_y` in the paper).
        let (random_add_coeff_ciphertext_1, random_add_coeff_nonce_1) = input
            .encryption_key_1
            .encrypt(rng, &random_add_coeff)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        // Compute a ring-Pedersen commitment of the random multiplicative
        // coefficient (producing `E` and `ɣ` in the paper).
        let (random_mult_coeff_commit, random_mult_coeff_commit_randomness) = input
            .verifier_setup_params
            .scheme()
            .commit(&random_mult_coeff, ELL + EPSILON, rng);
        // Compute a ring-Pedersen commitment of the secret multiplicative
        // coefficient (producing `S` and `m` in the paper).
        let (mult_coeff_commit, mult_coeff_commit_randomness) = input
            .verifier_setup_params
            .scheme()
            .commit(&secret.mult_coeff, ELL, rng);
        // Compute a ring-Pedersen commitment of the random additive coefficient
        // (producing `F` and `δ` in the paper).
        let (random_add_coeff_commit, random_add_coeff_commit_randomness) = input
            .verifier_setup_params
            .scheme()
            .commit(&random_add_coeff, ELL + EPSILON, rng);
        // Compute a ring-Pedersen commitment of the secret additive coefficient
        // (producing `T` and `μ` in the paper).
        let (add_coeff_commit, add_coeff_commit_randomness) = input
            .verifier_setup_params
            .scheme()
            .commit(&secret.add_coeff, ELL, rng);
        // Generate verifier's challenge via Fiat-Shamir (`e` in the paper).
        let challenge = Self::generate_challenge(
            transcript,
            context,
            input,
            &mult_coeff_commit,
            &add_coeff_commit,
            &random_affine_ciphertext,
            &random_mult_coeff_exp,
            &random_add_coeff_ciphertext_1,
            &random_mult_coeff_commit,
            &random_add_coeff_commit,
        )?;
        // Mask the (secret) multiplicative coefficient (`z_1` in the paper).
        let masked_mult_coeff = &random_mult_coeff + &challenge * &secret.mult_coeff;
        // Mask the (secret) additive coefficient (`z_2` in the paper).
        let masked_add_coeff = &random_add_coeff + &challenge * &secret.add_coeff;
        // Mask the multiplicative coefficient's commitment randomness (`z_3` in the
        // paper).
        let masked_mult_coeff_commit_randomness =
            mult_coeff_commit_randomness.mask(&random_mult_coeff_commit_randomness, &challenge);
        // Mask the additive coefficient's commitment randomness (`z_4` in the paper).
        let masked_add_coeff_commit_randomness =
            add_coeff_commit_randomness.mask(&random_add_coeff_commit_randomness, &challenge);
        // Mask the (secret) additive coefficient's nonce using the random
        // additive coefficient's nonce produced using the 0th encryption key
        // (`w` in the paper).
        let masked_add_coeff_nonce_0 = input.encryption_key_0.mask(
            &secret.add_coeff_nonce_0,
            &random_add_coeff_nonce_0,
            &challenge,
        );
        // Mask the (secret) additive coefficient's nonce using the random
        // additive coefficient's nonce produced using the 1st encryption key
        // (`w_y` in the paper).
        let masked_add_coeff_nonce_1 = input.encryption_key_1.mask(
            &secret.add_coeff_nonce_1,
            &random_add_coeff_nonce_1,
            &challenge,
        );
        Ok(Self {
            random_mult_coeff,
            random_add_coeff,
            mult_coeff_commit,
            add_coeff_commit,
            random_affine_ciphertext,
            random_mult_coeff_exp,
            random_add_coeff_ciphertext_1,
            random_mult_coeff_commit,
            random_add_coeff_commit,
            challenge,
            masked_mult_coeff,
            masked_add_coeff,
            masked_mult_coeff_commit_randomness,
            masked_add_coeff_commit_randomness,
            masked_add_coeff_nonce_0,
            masked_add_coeff_nonce_1,
        })
    }

    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    fn verify(
        &self,
        input: &Self::CommonInput,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        // Generate verifier's challenge via Fiat-Shamir...
        let challenge: BigNumber = Self::generate_challenge(
            transcript,
            context,
            input,
            &self.mult_coeff_commit,
            &self.add_coeff_commit,
            &self.random_affine_ciphertext,
            &self.random_mult_coeff_exp,
            &self.random_add_coeff_ciphertext_1,
            &self.random_mult_coeff_commit,
            &self.random_add_coeff_commit,
        )?;
        // ... and check that it's the correct challenge.
        if challenge != self.challenge {
            warn!("Fiat-Shamir consistency check failed");
            return Err(InternalError::ProtocolError);
        }
        // Check that the affine-like transformation holds over the masked
        // coefficients using the 0th encryption key.
        let masked_affine_operation_is_valid = {
            let tmp = input
                .encryption_key_0
                .encrypt_with_nonce(&self.masked_add_coeff, &self.masked_add_coeff_nonce_0)
                .map_err(|_| InternalError::InternalInvariantFailed)?;
            let lhs = input
                .encryption_key_0
                .multiply_and_add(&self.masked_mult_coeff, &input.input_ciphertext, &tmp)
                .map_err(|_| InternalError::InternalInvariantFailed)?;
            let rhs = input
                .encryption_key_0
                .multiply_and_add(
                    &self.challenge,
                    &input.output_ciphertext,
                    &self.random_affine_ciphertext,
                )
                .map_err(|_| InternalError::InternalInvariantFailed)?;
            lhs == rhs
        };
        if !masked_affine_operation_is_valid {
            warn!("Masked affine operation check (first equality check) failed");
            return Err(InternalError::ProtocolError);
        }
        // Check that the masked group exponentiation is valid.
        let masked_group_exponentiation_is_valid = {
            let lhs = CurvePoint::GENERATOR.multiply_by_scalar(&self.masked_mult_coeff)?;
            let rhs = self.random_mult_coeff_exp
                + input
                    .multiplicative_coefficient_exponentiation
                    .multiply_by_scalar(&self.challenge)?;
            lhs == rhs
        };
        if !masked_group_exponentiation_is_valid {
            warn!("Masked group exponentiation check (second equality check) failed");
            return Err(InternalError::ProtocolError);
        }
        // Check that the masked additive coefficient is valid using the 1st encryption
        // key.
        let masked_additive_coefficient_is_valid = {
            let lhs = input
                .encryption_key_1
                .encrypt_with_nonce(&self.masked_add_coeff, &self.masked_add_coeff_nonce_1)
                .map_err(|_| InternalError::InternalInvariantFailed)?;
            let rhs = input
                .encryption_key_1
                .multiply_and_add(
                    &self.challenge,
                    &input.additive_coefficient_ciphertext,
                    &self.random_add_coeff_ciphertext_1,
                )
                .map_err(|_| InternalError::InternalInvariantFailed)?;
            lhs == rhs
        };
        if !masked_additive_coefficient_is_valid {
            warn!("Masked additive coefficient check (third equality check) failed");
            return Err(InternalError::ProtocolError);
        }
        // Check that the masked multiplicative coefficient commitment is valid.
        let masked_mult_coeff_commit_is_valid = {
            let lhs = input.verifier_setup_params.scheme().reconstruct(
                &self.masked_mult_coeff,
                &self.masked_mult_coeff_commit_randomness,
            );
            let rhs = input.verifier_setup_params.scheme().combine(
                &self.random_mult_coeff_commit,
                &self.mult_coeff_commit,
                &self.challenge,
            );
            lhs == rhs
        };
        if !masked_mult_coeff_commit_is_valid {
            warn!(
                "Masked multiplicative coefficient commitment check (fourth equality check) failed"
            );
            return Err(InternalError::ProtocolError);
        }
        // Check that the masked additive coefficient commitment is valid.
        let masked_add_coeff_commit_is_valid = {
            let lhs = input.verifier_setup_params.scheme().reconstruct(
                &self.masked_add_coeff,
                &self.masked_add_coeff_commit_randomness,
            );
            let rhs = input.verifier_setup_params.scheme().combine(
                &self.random_add_coeff_commit,
                &self.add_coeff_commit,
                &self.challenge,
            );
            lhs == rhs
        };
        if !masked_add_coeff_commit_is_valid {
            warn!("Masked additive coefficient commitment check (fifth equality check) failed");
            return Err(InternalError::ProtocolError);
        }
        // Do a range check on the masked multiplicative coefficient.
        if !within_bound_by_size(&self.masked_mult_coeff, ELL + EPSILON) {
            warn!("Multiplicative coefficient range check failed");
            return Err(InternalError::ProtocolError);
        }
        // Do a range check on the masked additive coefficient.
        if !within_bound_by_size(&self.masked_add_coeff, ELL_PRIME + EPSILON) {
            warn!(" coefficient range check failed");
            return Err(InternalError::ProtocolError);
        }
        Ok(())
    }
}

impl PiAffgProof {
    #[allow(clippy::too_many_arguments)]
    fn generate_challenge(
        transcript: &mut Transcript,
        context: &impl ProofContext,
        input: &PiAffgInput,
        mult_coeff_commit: &Commitment,
        add_coeff_commit: &Commitment,
        random_affine_ciphertext: &Ciphertext,
        random_mult_coeff_exp: &CurvePoint,
        random_add_coeff_ciphertext_1: &Ciphertext,
        random_mult_coeff_commit: &Commitment,
        random_add_coeff_commit: &Commitment,
    ) -> Result<BigNumber> {
        transcript.append_message(
            b"Paillier Affine Operation Proof Context",
            &context.as_bytes()?,
        );
        transcript.append_message(
            b"Paillier Affine Operation Common Input",
            &serialize!(&input)?,
        );
        transcript.append_message(
            b"(mult_coeff_commit, add_coeff_commit, random_affine_ciphertext, random_mult_coeff_exp, random_add_coeff_ciphertext_1, random_mult_coeff_commit, random_add_coeff_commit)",
            &[
                mult_coeff_commit.to_bytes(),
                add_coeff_commit.to_bytes(),
                random_affine_ciphertext.to_bytes(),
                serialize!(&random_mult_coeff_exp).unwrap(),
                random_add_coeff_ciphertext_1.to_bytes(),
                random_mult_coeff_commit.to_bytes(),
                random_add_coeff_commit.to_bytes(),
            ]
            .concat(),
        );
        Ok(plusminus_bn_random_from_transcript(
            transcript,
            &k256_order(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        paillier::DecryptionKey,
        utils::{random_plusminus_by_size_with_minimum, testing::init_testing},
        zkp::BadContext,
    };

    fn random_paillier_affg_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
        y: &BigNumber,
    ) -> Result<(PiAffgProof, PiAffgInput, Transcript)> {
        let (decryption_key_0, _, _) = DecryptionKey::new(rng).unwrap();
        let pk0 = decryption_key_0.encryption_key();

        let (decryption_key_1, _, _) = DecryptionKey::new(rng).unwrap();
        let pk1 = decryption_key_1.encryption_key();

        let generator = CurvePoint::GENERATOR;
        let X = generator.multiply_by_scalar(x)?;
        let (Y, rho_y) = pk1
            .encrypt(rng, y)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let C = pk0.random_ciphertext(rng);

        // Compute D = C^x * (1 + N0)^y rho^N0 (mod N0^2)
        let (D, rho) = {
            let (D_intermediate, rho) = pk0.encrypt(rng, y).unwrap();
            let D = pk0.multiply_and_add(x, &C, &D_intermediate).unwrap();
            (D, rho)
        };

        let setup_params = VerifiedRingPedersen::gen(rng, &())?;
        let mut transcript = Transcript::new(b"random_paillier_affg_proof");
        let input = PiAffgInput::new(setup_params, pk0, pk1, C, D, Y, X);

        let proof = PiAffgProof::prove(
            &input,
            &PiAffgSecret::new(x.clone(), y.clone(), rho, rho_y),
            &(),
            &mut transcript,
            rng,
        )?;
        let transcript = Transcript::new(b"random_paillier_affg_proof");
        Ok((proof, input, transcript))
    }

    fn random_paillier_affg_verified_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
        y: &BigNumber,
    ) -> Result<()> {
        let (proof, input, mut transcript) = random_paillier_affg_proof(rng, x, y)?;
        proof.verify(&input, &(), &mut transcript)
    }

    #[test]
    fn test_paillier_affg_proof() -> Result<()> {
        let mut rng = init_testing();

        let x_small = random_plusminus_by_size(&mut rng, ELL);
        let y_small = random_plusminus_by_size(&mut rng, ELL_PRIME);
        let x_large =
            random_plusminus_by_size_with_minimum(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;
        let y_large = random_plusminus_by_size_with_minimum(
            &mut rng,
            ELL_PRIME + EPSILON + 1,
            ELL_PRIME + EPSILON,
        )?;

        // Sampling x in 2^ELL and y in 2^{ELL_PRIME} should always succeed
        random_paillier_affg_verified_proof(&mut rng, &x_small, &y_small)?;

        // All other combinations should fail
        assert!(random_paillier_affg_verified_proof(&mut rng, &x_small, &y_large).is_err());
        assert!(random_paillier_affg_verified_proof(&mut rng, &x_large, &y_small).is_err());
        assert!(random_paillier_affg_verified_proof(&mut rng, &x_large, &y_large).is_err());

        Ok(())
    }

    #[test]
    fn piaffg_proof_context_must_be_correct() -> Result<()> {
        let mut rng = init_testing();

        let x_small = random_plusminus_by_size(&mut rng, ELL);
        let y_small = random_plusminus_by_size(&mut rng, ELL_PRIME);

        let context = BadContext {};
        let (proof, input, mut transcript) =
            random_paillier_affg_proof(&mut rng, &x_small, &y_small).unwrap();
        let result = proof.verify(&input, &context, &mut transcript);
        assert!(result.is_err());
        Ok(())
    }
}
