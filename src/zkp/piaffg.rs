// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof of knowledge of a Paillier affine
//! operation with a group commitment where the encrypted and committed values
//! are in a given range.
//!
//! More precisely, this module includes methods to create and verify a
//! non-interactive zero-knowledge proof of knowledge of `(x, y, ρ, ρ_y)`,
//! where:
//! - `x` (the _multiplicative coefficient_) is the discrete log of a public
//!   group element and lies in the range `I`;
//! - `y` (the _additive coefficient_) lies in the range `J`;
//! - `(y, ρ_y)` is the (plaintext, nonce) pair corresponding to a public
//!   ciphertext `Y` encrypted using the prover's encryption key;
//! - `(y, ρ)` is the (plaintext, nonce) pair corresponding to a ciphertext `Y'`
//!   encrypted using the verifier's encryption key; and
//! - the relation `D = C^x · Y'` holds for public ciphertexts `C` and `D`
//!   encrypted using the verifier's encryption key.
//!
//! Note that all ciphertexts are encrypted under the verifier's Paillier
//! encryption key except for `Y`, which is under the prover's Paillier
//! encryption key. The acceptable range for the plaintexts are fixed according
//! to our parameters: `I = [-2^ℓ, 2^ℓ]`, where `ℓ` is [`ELL`] and `J = [-2^ℓ',
//! 2^ℓ']`, where `ℓ'` is [`ELL_PRIME`].
//!
//! The proof is defined in Figure 15 of CGGMP[^cite], and the implementation
//! uses a standard Fiat-Shamir transformation to make the proof
//! non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
//! Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts. [EPrint archive,
//! 2021](https://eprint.iacr.org/2021/060.pdf).

use crate::{
    errors::*,
    paillier::{Ciphertext, EncryptionKey, MaskedNonce, Nonce, PaillierError},
    parameters::{ELL, ELL_PRIME, EPSILON},
    ring_pedersen::{Commitment, MaskedRandomness, VerifiedRingPedersen},
    utils::{
        self, plusminus_challenge_from_transcript, random_plusminus_by_size, within_bound_by_size,
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

/// Zero-knowledge proof of knowledge of a Paillier affine operation with a
/// group commitment where the encrypted and committed values are in a given
/// range.
///
/// See the [module-level documentation](crate::zkp::piaffg) for more details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiAffgProof {
    /// A ring-Pedersen commitment to the multiplicative coefficient (`S` in the
    /// paper).
    mult_coeff_commit: Commitment,
    /// A ring-Pedersen commitment to the additive coefficient (`T` in the
    /// paper).
    add_coeff_commit: Commitment,
    /// A ciphertext produced by the affine-like transformation applied to the
    /// random multiplicative and random additive coefficients (`A` in the
    /// paper).
    random_affine_ciphertext_verifier: Ciphertext,
    /// A group exponentiation of the random multiplicative coefficient (`B_x`
    /// in the paper).
    random_mult_coeff_exp: CurvePoint,
    /// A Paillier ciphertext, under the prover's encryption key, of the
    /// random additive coefficient (`B_y` in the paper).
    random_add_coeff_ciphertext_prover: Ciphertext,
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
    /// coefficient under the verifier's encryption key (`w` in the paper).
    masked_add_coeff_nonce_verifier: MaskedNonce,
    /// A mask of the Paillier ciphertext nonce of the (secret) additive
    /// coefficient under the prover's encryption key (`w_y` in the paper).
    masked_add_coeff_nonce_prover: MaskedNonce,
}

/// Common input and setup parameters for [`PiAffgProof`] known to both the
/// prover and verifier.
#[derive(Serialize)]
pub(crate) struct PiAffgInput {
    /// The verifier's commitment parameters (`(Nhat, s, t)` in the paper).
    verifier_setup_params: VerifiedRingPedersen,
    /// The verifier's Paillier encryption key (`N_0` in the paper).
    verifier_encryption_key: EncryptionKey,
    /// The prover's Paillier encryption key (`N_1` in the paper).
    prover_encryption_key: EncryptionKey,
    /// The original Paillier ciphertext encrypted under the verifier's
    /// encryption key (`C` in the paper).
    original_ciphertext_verifier: Ciphertext,
    /// The transformed Paillier ciphertext encrypted under the verifier's
    /// encryption key (`D` in the paper).
    transformed_ciphertext_verifier: Ciphertext,
    /// Paillier ciphertext of the prover's additive coefficient under the
    /// prover's encryption key (`Y` in the paper).
    add_coeff_ciphertext_prover: Ciphertext,
    /// Exponentiation of the prover's multiplicative coefficient (`X` in the
    /// paper).
    mult_coeff_exp: CurvePoint,
}

impl PiAffgInput {
    /// Construct a new [`PiAffgInput`] type.
    pub(crate) fn new(
        verifier_setup_params: VerifiedRingPedersen,
        verifier_encryption_key: EncryptionKey,
        prover_encryption_key: EncryptionKey,
        original_ciphertext_verifier: Ciphertext,
        transformed_ciphertext_verifier: Ciphertext,
        add_coeff_ciphertext_prover: Ciphertext,
        mult_coeff_exp: CurvePoint,
    ) -> Self {
        Self {
            verifier_setup_params,
            verifier_encryption_key,
            prover_encryption_key,
            original_ciphertext_verifier,
            transformed_ciphertext_verifier,
            add_coeff_ciphertext_prover,
            mult_coeff_exp,
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
    /// The additive coefficient's nonce produced when encrypted using the
    /// verifier's encryption key (`ρ` in the paper).
    add_coeff_nonce_verifier_key: Nonce,
    /// The additive coefficient's nonce produced when encrypted using the
    /// prover's encryption key (`ρ_y` in the paper).
    add_coeff_nonce_prover_key: Nonce,
}

impl Debug for PiAffgSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paillier Affine Operation Proof Secret")
            .field("mult_coeff", &"[redacted]")
            .field("add_coeff", &"[redacted]")
            .field("add_coeff_nonce_verifier", &"[redacted]")
            .field("add_coeff_nonce_prover", &"[redacted]")
            .finish()
    }
}

impl PiAffgSecret {
    /// Construct a new [`PiAffgSecret`] type.
    pub(crate) fn new(
        mult_coeff: BigNumber,
        add_coeff: BigNumber,
        add_coeff_nonce_verifier_key: Nonce,
        add_coeff_nonce_prover_key: Nonce,
    ) -> Self {
        Self {
            mult_coeff,
            add_coeff,
            add_coeff_nonce_verifier_key,
            add_coeff_nonce_prover_key,
        }
    }
}

impl Proof for PiAffgProof {
    type CommonInput = PiAffgInput;
    type ProverSecret = PiAffgSecret;

    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
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
        // ciphertext values encrypted using the verifier's public key equates
        // to computing `z · x + y`, where `z` is some value encrypted by the
        // verifier as part of the public input, (2) `y` matches a ciphertext
        // encrypted under the _prover_'s encryption key, and (3) `x` and `y`
        // fall within acceptable ranges.
        //
        // In even more detail (all variable names refer to those used in the
        // paper), let `C_i[·]` denote the resulting ciphertext using either the
        // `p`rover's or the `v`erifier's encryption key. The prover wants to
        // prove the following three claims:
        //
        // 1. `C_v[z] ^ x · C_v[y] = D`, where `C_v[z]` is a public value
        //    provided by the verifier and `D` is a public value computed by the
        //    prover.
        //
        // 2. `C_p[y] = Y`, where `Y` is a public value provided by the prover.
        //
        // 3. `g ^ x = X`, where `X` is a public value provided by the prover.
        //
        // This is done as follows. First, the prover constructs such a
        // computation on _random_ values `ɑ` and `β` by computing `A = C_v[z] ^
        // ɑ · C_v[β]`. Likewise, it produces "encoded" versions of these random
        // values `B_x = g ^ ɑ` and `B_y = C_p[β]`. It then demonstrates the
        // following three conditions, using a challenge value `e` produced by
        // using Fiat-Shamir:
        //
        // 1. C_v[z] ^ (ɑ + e x) · C_v[β + e y] = A * D ^ e (note that if `D`
        //    "encodes" `z x + y` this check will pass)
        //
        // 2. g ^ (ɑ + e x) = B_x · X ^ e (note that if `X = g ^ x` this check
        //    will pass)
        //
        // 3. C_p[β + e y] = B_y · Y ^ e (note that if `Y = C_p[y]` this check
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
        // Encrypt the random additive coefficient using the verifier's encryption key.
        let (random_additive_coeff_ciphertext_verifier, random_add_coeff_nonce_verifier) = input
            .verifier_encryption_key
            .encrypt(rng, &random_add_coeff)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        // Compute the affine-like operation on our random coefficients and the
        // input ciphertext using the verifier's encryption key (producing `A` in the
        // paper).
        let random_affine_ciphertext_verifier = input
            .verifier_encryption_key
            .multiply_and_add(
                &random_mult_coeff,
                &input.original_ciphertext_verifier,
                &random_additive_coeff_ciphertext_verifier,
            )
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        // Compute the exponentiation of the random multiplicative coefficient
        // (producing `B_x` in the paper)
        let random_mult_coeff_exp = CurvePoint::GENERATOR.multiply_by_scalar(&random_mult_coeff)?;
        // Encrypt the random additive coefficient using the 1st encryption key
        // (producing `B_y` in the paper).
        let (random_add_coeff_ciphertext_prover, random_add_coeff_nonce_prover) = input
            .prover_encryption_key
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
            &random_affine_ciphertext_verifier,
            &random_mult_coeff_exp,
            &random_add_coeff_ciphertext_prover,
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
        // additive coefficient's nonce produced using the verifier's encryption
        // key (`w` in the paper).
        let masked_add_coeff_nonce_verifier = input.verifier_encryption_key.mask(
            &secret.add_coeff_nonce_verifier_key,
            &random_add_coeff_nonce_verifier,
            &challenge,
        );
        // Mask the (secret) additive coefficient's nonce using the random
        // additive coefficient's nonce produced using the prover's encryption
        // key (`w_y` in the paper).
        let masked_add_coeff_nonce_prover = input.prover_encryption_key.mask(
            &secret.add_coeff_nonce_prover_key,
            &random_add_coeff_nonce_prover,
            &challenge,
        );
        Ok(Self {
            mult_coeff_commit,
            add_coeff_commit,
            random_affine_ciphertext_verifier,
            random_mult_coeff_exp,
            random_add_coeff_ciphertext_prover,
            random_mult_coeff_commit,
            random_add_coeff_commit,
            challenge,
            masked_mult_coeff,
            masked_add_coeff,
            masked_mult_coeff_commit_randomness,
            masked_add_coeff_commit_randomness,
            masked_add_coeff_nonce_verifier,
            masked_add_coeff_nonce_prover,
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
        let challenge = Self::generate_challenge(
            transcript,
            context,
            input,
            &self.mult_coeff_commit,
            &self.add_coeff_commit,
            &self.random_affine_ciphertext_verifier,
            &self.random_mult_coeff_exp,
            &self.random_add_coeff_ciphertext_prover,
            &self.random_mult_coeff_commit,
            &self.random_add_coeff_commit,
        )?;
        // ... and check that it's the correct challenge.
        if challenge != self.challenge {
            warn!("Fiat-Shamir consistency check failed");
            return Err(InternalError::ProtocolError);
        }
        // Check that the affine-like transformation holds over the masked
        // coefficients using the verifier's encryption key.
        let masked_affine_operation_is_valid = || -> std::result::Result<bool, PaillierError> {
            let tmp = input.verifier_encryption_key.encrypt_with_nonce(
                &self.masked_add_coeff,
                &self.masked_add_coeff_nonce_verifier,
            )?;
            let lhs = input.verifier_encryption_key.multiply_and_add(
                &self.masked_mult_coeff,
                &input.original_ciphertext_verifier,
                &tmp,
            )?;
            let rhs = input.verifier_encryption_key.multiply_and_add(
                &self.challenge,
                &input.transformed_ciphertext_verifier,
                &self.random_affine_ciphertext_verifier,
            )?;
            Ok(lhs == rhs)
        }()
        .map_err(|_| InternalError::InternalInvariantFailed)?;
        if !masked_affine_operation_is_valid {
            warn!("Masked affine operation check (first equality check) failed");
            return Err(InternalError::ProtocolError);
        }
        // Check that the masked group exponentiation is valid.
        let masked_group_exponentiation_is_valid = {
            let lhs = CurvePoint::GENERATOR.multiply_by_scalar(&self.masked_mult_coeff)?;
            let rhs = self.random_mult_coeff_exp
                + input.mult_coeff_exp.multiply_by_scalar(&self.challenge)?;
            lhs == rhs
        };
        if !masked_group_exponentiation_is_valid {
            warn!("Masked group exponentiation check (second equality check) failed");
            return Err(InternalError::ProtocolError);
        }
        // Check that the masked additive coefficient is valid using the
        // prover's encryption key.
        let masked_additive_coefficient_is_valid = {
            let lhs = input
                .prover_encryption_key
                .encrypt_with_nonce(&self.masked_add_coeff, &self.masked_add_coeff_nonce_prover)
                .map_err(|_| InternalError::ProtocolError)?;
            let rhs = input
                .prover_encryption_key
                .multiply_and_add(
                    &self.challenge,
                    &input.add_coeff_ciphertext_prover,
                    &self.random_add_coeff_ciphertext_prover,
                )
                .map_err(|_| InternalError::ProtocolError)?;
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
            warn!("Additive coefficient range check failed");
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
        random_add_coeff_ciphertext_prover: &Ciphertext,
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
            b"(mult_coeff_commit, add_coeff_commit, random_affine_ciphertext, random_mult_coeff_exp, random_add_coeff_ciphertext_prover, random_mult_coeff_commit, random_add_coeff_commit)",
            &[
                mult_coeff_commit.to_bytes(),
                add_coeff_commit.to_bytes(),
                random_affine_ciphertext.to_bytes(),
                serialize!(&random_mult_coeff_exp)?,
                random_add_coeff_ciphertext_prover.to_bytes(),
                random_mult_coeff_commit.to_bytes(),
                random_add_coeff_commit.to_bytes(),
            ]
            .concat(),
        );

        plusminus_challenge_from_transcript(transcript)
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

        let X = CurvePoint::GENERATOR.multiply_by_scalar(x)?;
        let (Y, rho_y) = pk1
            .encrypt(rng, y)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let C = pk0.random_ciphertext(rng);

        let (D, rho) = {
            let (D_intermediate, rho) = pk0.encrypt(rng, y).unwrap();
            let D = pk0.multiply_and_add(x, &C, &D_intermediate).unwrap();
            (D, rho)
        };

        let setup_params = VerifiedRingPedersen::gen(rng, &())?;
        let mut transcript = Transcript::new(b"random_paillier_affg_proof");
        let input = PiAffgInput::new(setup_params, pk0, pk1, C, D, Y, X);
        let secret = PiAffgSecret::new(x.clone(), y.clone(), rho, rho_y);

        let proof = PiAffgProof::prove(&input, &secret, &(), &mut transcript, rng)?;
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
