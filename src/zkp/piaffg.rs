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
//! 2021](https://eprint.iacr.org/archive/2021/060/1634824619.pdf).

use crate::{
    curve::CurveTrait,
    errors::*,
    paillier::{Ciphertext, EncryptionKey, MaskedNonce, Nonce, PaillierError},
    parameters::{ELL, ELL_PRIME, EPSILON},
    ring_pedersen::{Commitment, MaskedRandomness, VerifiedRingPedersen},
    utils::{plusminus_challenge_from_transcript, random_plusminus_by_size, within_bound_by_size},
    zkp::{Proof, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;

/// Zero-knowledge proof of knowledge of a Paillier affine operation with a
/// group commitment where the encrypted and committed values are in a given
/// range.
///
/// See the [module-level documentation](crate::zkp::piaffg) for more details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiAffgProof<C> {
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
    random_mult_coeff_exp: C,
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
///
/// Copying/Cloning references is harmless and sometimes necessary. So we
/// implement Clone and Copy for this type.
#[derive(Serialize, Clone, Copy)]
pub(crate) struct PiAffgInput<'a, C> {
    /// The verifier's commitment parameters (`(Nhat, s, t)` in the paper).
    verifier_setup_params: &'a VerifiedRingPedersen,
    /// The verifier's Paillier encryption key (`N_0` in the paper).
    verifier_encryption_key: &'a EncryptionKey,
    /// The prover's Paillier encryption key (`N_1` in the paper).
    prover_encryption_key: &'a EncryptionKey,
    /// The original Paillier ciphertext encrypted under the verifier's
    /// encryption key (`C` in the paper).
    original_ciphertext_verifier: &'a Ciphertext,
    /// The transformed Paillier ciphertext encrypted under the verifier's
    /// encryption key (`D` in the paper).
    transformed_ciphertext_verifier: &'a Ciphertext,
    /// Paillier ciphertext of the prover's additive coefficient under the
    /// prover's encryption key (`Y` in the paper).
    add_coeff_ciphertext_prover: &'a Ciphertext,
    /// Exponentiation of the prover's multiplicative coefficient (`X` in the
    /// paper).
    mult_coeff_exp: &'a C,
}

impl<'a, C> PiAffgInput<'a, C> {
    /// Construct a new [`PiAffgInput`] type.
    pub(crate) fn new(
        verifier_setup_params: &'a VerifiedRingPedersen,
        verifier_encryption_key: &'a EncryptionKey,
        prover_encryption_key: &'a EncryptionKey,
        original_ciphertext_verifier: &'a Ciphertext,
        transformed_ciphertext_verifier: &'a Ciphertext,
        add_coeff_ciphertext_prover: &'a Ciphertext,
        mult_coeff_exp: &'a C,
    ) -> PiAffgInput<'a, C> {
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
pub(crate) struct PiAffgSecret<'a> {
    /// The multiplicative coefficient (`x` in the paper).
    mult_coeff: &'a BigNumber,
    /// The additive coefficient (`y` in the paper).
    add_coeff: &'a BigNumber,
    /// The additive coefficient's nonce produced when encrypted using the
    /// verifier's encryption key (`ρ` in the paper).
    add_coeff_nonce_verifier_key: &'a Nonce,
    /// The additive coefficient's nonce produced when encrypted using the
    /// prover's encryption key (`ρ_y` in the paper).
    add_coeff_nonce_prover_key: &'a Nonce,
}

impl Debug for PiAffgSecret<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paillier Affine Operation Proof Secret")
            .field("mult_coeff", &"[redacted]")
            .field("add_coeff", &"[redacted]")
            .field("add_coeff_nonce_verifier", &"[redacted]")
            .field("add_coeff_nonce_prover", &"[redacted]")
            .finish()
    }
}

impl<'a> PiAffgSecret<'a> {
    /// Construct a new [`PiAffgSecret`] type.
    pub(crate) fn new(
        mult_coeff: &'a BigNumber,
        add_coeff: &'a BigNumber,
        add_coeff_nonce_verifier_key: &'a Nonce,
        add_coeff_nonce_prover_key: &'a Nonce,
    ) -> PiAffgSecret<'a> {
        Self {
            mult_coeff,
            add_coeff,
            add_coeff_nonce_verifier_key,
            add_coeff_nonce_prover_key,
        }
    }
}

impl<C: CurveTrait> Proof for PiAffgProof<C> {
    type CommonInput<'a> = PiAffgInput<'a, C>;
    type ProverSecret<'b> = PiAffgSecret<'b>;

    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: Self::CommonInput<'_>,
        secret: Self::ProverSecret<'_>,
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
        // 1. `C_v[z] ^ x · C_v[y] = D`, where `C_v[z]` is a public value provided by
        //    the verifier and `D` is a public value computed by the prover.
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
        // 1. C_v[z] ^ (ɑ + e x) · C_v[β + e y] = A * D ^ e (note that if `D` "encodes"
        //    `z x + y` this check will pass)
        //
        // 2. g ^ (ɑ + e x) = B_x · X ^ e (note that if `X = g ^ x` this check will
        //    pass)
        //
        // 3. C_p[β + e y] = B_y · Y ^ e (note that if `Y = C_p[y]` this check will
        //    pass)
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
                input.original_ciphertext_verifier,
                &random_additive_coeff_ciphertext_verifier,
            )
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        // Compute the exponentiation of the random multiplicative coefficient
        // (producing `B_x` in the paper)
        let random_mult_coeff_exp = C::scale_generator(&random_mult_coeff)?;
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
            .commit(secret.mult_coeff, ELL, rng);
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
            .commit(secret.add_coeff, ELL, rng);
        // Generate verifier's challenge via Fiat-Shamir (`e` in the paper).
        let challenge = Self::generate_challenge(
            transcript,
            context,
            &input,
            &mult_coeff_commit,
            &add_coeff_commit,
            &random_affine_ciphertext_verifier,
            &random_mult_coeff_exp,
            &random_add_coeff_ciphertext_prover,
            &random_mult_coeff_commit,
            &random_add_coeff_commit,
        )?;
        // Mask the (secret) multiplicative coefficient (`z_1` in the paper).
        let masked_mult_coeff = &random_mult_coeff + &challenge * secret.mult_coeff;
        // Mask the (secret) additive coefficient (`z_2` in the paper).
        let masked_add_coeff = &random_add_coeff + &challenge * secret.add_coeff;
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
            secret.add_coeff_nonce_verifier_key,
            &random_add_coeff_nonce_verifier,
            &challenge,
        );
        // Mask the (secret) additive coefficient's nonce using the random
        // additive coefficient's nonce produced using the prover's encryption
        // key (`w_y` in the paper).
        let masked_add_coeff_nonce_prover = input.prover_encryption_key.mask(
            secret.add_coeff_nonce_prover_key,
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
        self,
        input: Self::CommonInput<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        // Generate verifier's challenge via Fiat-Shamir...
        let challenge = Self::generate_challenge(
            transcript,
            context,
            &input,
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
            error!("Fiat-Shamir consistency check failed");
            return Err(InternalError::ProtocolError(None));
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
                input.original_ciphertext_verifier,
                &tmp,
            )?;
            let rhs = input.verifier_encryption_key.multiply_and_add(
                &self.challenge,
                input.transformed_ciphertext_verifier,
                &self.random_affine_ciphertext_verifier,
            )?;
            Ok(lhs == rhs)
        }()
        .map_err(|_| InternalError::InternalInvariantFailed)?;
        if !masked_affine_operation_is_valid {
            error!("Masked affine operation check (first equality check) failed");
            return Err(InternalError::ProtocolError(None));
        }
        // Check that the masked group exponentiation is valid.
        let masked_group_exponentiation_is_valid = {
            let lhs = C::scale_generator(&self.masked_mult_coeff)?;
            let rhs =
                self.random_mult_coeff_exp + input.mult_coeff_exp.mul_by_bn(&self.challenge)?;
            lhs == rhs
        };
        if !masked_group_exponentiation_is_valid {
            error!("Masked group exponentiation check (second equality check) failed");
            return Err(InternalError::ProtocolError(None));
        }
        // Check that the masked additive coefficient is valid using the
        // prover's encryption key.
        let masked_additive_coefficient_is_valid = {
            let lhs = input
                .prover_encryption_key
                .encrypt_with_nonce(&self.masked_add_coeff, &self.masked_add_coeff_nonce_prover)
                .map_err(|_| InternalError::ProtocolError(None))?;
            let rhs = input
                .prover_encryption_key
                .multiply_and_add(
                    &self.challenge,
                    input.add_coeff_ciphertext_prover,
                    &self.random_add_coeff_ciphertext_prover,
                )
                .map_err(|_| InternalError::ProtocolError(None))?;
            lhs == rhs
        };
        if !masked_additive_coefficient_is_valid {
            error!("Masked additive coefficient check (third equality check) failed");
            return Err(InternalError::ProtocolError(None));
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
            error!(
                "Masked multiplicative coefficient commitment check (fourth equality check) failed"
            );
            return Err(InternalError::ProtocolError(None));
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
            error!("Masked additive coefficient commitment check (fifth equality check) failed");
            return Err(InternalError::ProtocolError(None));
        }
        // Do a range check on the masked multiplicative coefficient.
        if !within_bound_by_size(&self.masked_mult_coeff, ELL + EPSILON) {
            error!("Multiplicative coefficient range check failed");
            return Err(InternalError::ProtocolError(None));
        }
        // Do a range check on the masked additive coefficient.
        if !within_bound_by_size(&self.masked_add_coeff, ELL_PRIME + EPSILON) {
            error!("Additive coefficient range check failed");
            return Err(InternalError::ProtocolError(None));
        }
        Ok(())
    }
}

impl<C: CurveTrait> PiAffgProof<C> {
    #[allow(clippy::too_many_arguments)]
    fn generate_challenge(
        transcript: &mut Transcript,
        context: &impl ProofContext,
        input: &PiAffgInput<C>,
        mult_coeff_commit: &Commitment,
        add_coeff_commit: &Commitment,
        random_affine_ciphertext: &Ciphertext,
        random_mult_coeff_exp: &C,
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

        plusminus_challenge_from_transcript::<C>(transcript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::{CurveTrait, TestCurve as C},
        paillier::DecryptionKey,
        utils::{random_plusminus, random_plusminus_by_size_with_minimum, testing::init_testing},
        zkp::BadContext,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};
    type PiAffgProof = super::PiAffgProof<C>;
    type PiAffgInput<'a> = super::PiAffgInput<'a, C>;

    // Type of expected function for our code testing.
    type TestFn = fn(PiAffgProof, PiAffgInput) -> Result<()>;

    fn transcript() -> Transcript {
        Transcript::new(b"random_paillier_affg_proof")
    }

    fn with_random_paillier_affg_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
        y: &BigNumber,
        mut test_code: impl FnMut(PiAffgProof, PiAffgInput) -> Result<()>,
    ) -> Result<()> {
        let (decryption_key_0, _, _) = DecryptionKey::new(rng).unwrap();
        let pk0 = decryption_key_0.encryption_key();

        let (decryption_key_1, _, _) = DecryptionKey::new(rng).unwrap();
        let pk1 = decryption_key_1.encryption_key();

        let mult_coeff_exp = C::GENERATOR.multiply_by_bignum(x)?;
        let (add_coeff_ciphertext_prover, rho_y) = pk1
            .encrypt(rng, y)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let original_ciphertext_verifier = pk0.random_ciphertext(rng);

        let (transformed_ciphertext_verifier, rho) = {
            let (transformed_ciphertext_verifier_intermediate, rho) = pk0.encrypt(rng, y).unwrap();
            let transformed_ciphertext_verifier = pk0
                .multiply_and_add(
                    x,
                    &original_ciphertext_verifier,
                    &transformed_ciphertext_verifier_intermediate,
                )
                .unwrap();
            (transformed_ciphertext_verifier, rho)
        };

        let setup_params = VerifiedRingPedersen::gen(rng, &())?;
        let input = PiAffgInput::new(
            &setup_params,
            &pk0,
            &pk1,
            &original_ciphertext_verifier,
            &transformed_ciphertext_verifier,
            &add_coeff_ciphertext_prover,
            &mult_coeff_exp,
        );
        let secret = PiAffgSecret::new(x, y, &rho, &rho_y);

        let proof = PiAffgProof::prove(input, secret, &(), &mut transcript(), rng)?;
        test_code(proof, input)?;
        Ok(())
    }

    fn random_paillier_affg_verified_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
        y: &BigNumber,
    ) -> Result<()> {
        let f: TestFn = |proof, input| proof.verify(input, &(), &mut transcript());
        with_random_paillier_affg_proof(rng, x, y, f)
    }

    #[test]
    fn piaffg_proof_with_consistent_secret_inputs_out_of_range() -> Result<()> {
        let mut rng = init_testing();
        let x_upper_bound = BigNumber::one() << (ELL + EPSILON);
        let y_upper_bound = BigNumber::one() << (ELL_PRIME + EPSILON);
        let x = random_plusminus_by_size(&mut rng, ELL);
        let y = random_plusminus_by_size(&mut rng, ELL_PRIME);
        let f: TestFn = |bad_proof, input| {
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
            Ok(())
        };
        let x_too_large =
            random_plusminus_by_size_with_minimum(&mut rng, ELL + EPSILON + 2, ELL + EPSILON + 1)?;
        let x_too_small = -x_too_large.clone();
        assert!(x_too_large > x_upper_bound || x_too_small > x_upper_bound);
        with_random_paillier_affg_proof(&mut rng, &x_too_large, &y, f)?;
        with_random_paillier_affg_proof(&mut rng, &x_too_small, &y, f)?;
        let y_too_large = random_plusminus_by_size_with_minimum(
            &mut rng,
            ELL_PRIME + EPSILON + 2,
            ELL_PRIME + EPSILON + 1,
        )?;
        let y_too_small = -y_too_large.clone();
        assert!(y_too_large > y_upper_bound || y_too_small > y_upper_bound);
        with_random_paillier_affg_proof(&mut rng, &x, &y_too_large, f)?;
        with_random_paillier_affg_proof(&mut rng, &x, &y_too_small, f)?;
        with_random_paillier_affg_proof(&mut rng, &x_too_large, &y_too_large, f)?;
        with_random_paillier_affg_proof(&mut rng, &x_too_small, &y_too_small, f)?;
        Ok(())
    }

    #[test]
    fn piaffg_proof_with_different_setup_parameters() -> Result<()> {
        let mut rng = init_testing();
        let x = random_plusminus_by_size(&mut rng, ELL);
        let y = random_plusminus_by_size(&mut rng, ELL_PRIME);
        let rng2 = &mut StdRng::from_seed(rng.gen());

        let f = |proof: PiAffgProof, input: PiAffgInput| {
            // Swap verifier setup parameters with a random [`VerifiedRingPedersen`]
            let bad_setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
            assert_ne!(bad_setup_params, input.verifier_setup_params.clone());
            let bad_input = PiAffgInput::new(
                &bad_setup_params,
                input.verifier_encryption_key,
                input.prover_encryption_key,
                input.original_ciphertext_verifier,
                input.transformed_ciphertext_verifier,
                input.add_coeff_ciphertext_prover,
                input.mult_coeff_exp,
            );
            assert!(proof
                .clone()
                .verify(bad_input, &(), &mut transcript())
                .is_err());

            // Swap verifier encryption key with a random [`EncryptionKey`]
            let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
            let bad_verifier_encryption_key = decryption_key.encryption_key();
            assert_ne!(
                bad_verifier_encryption_key,
                input.verifier_encryption_key.clone()
            );
            let bad_input = PiAffgInput::new(
                input.verifier_setup_params,
                &bad_verifier_encryption_key,
                input.prover_encryption_key,
                input.original_ciphertext_verifier,
                input.transformed_ciphertext_verifier,
                input.add_coeff_ciphertext_prover,
                input.mult_coeff_exp,
            );
            assert!(proof
                .clone()
                .verify(bad_input, &(), &mut transcript())
                .is_err());

            // Swap prover encryption key with a random [`EncryptionKey`]
            let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
            let bad_prover_encryption_key = decryption_key.encryption_key();
            assert_ne!(
                bad_prover_encryption_key,
                input.prover_encryption_key.clone()
            );
            let bad_input = PiAffgInput::new(
                input.verifier_setup_params,
                input.verifier_encryption_key,
                &bad_prover_encryption_key,
                input.original_ciphertext_verifier,
                input.transformed_ciphertext_verifier,
                input.add_coeff_ciphertext_prover,
                input.mult_coeff_exp,
            );
            assert!(proof
                .clone()
                .verify(bad_input, &(), &mut transcript())
                .is_err());

            // Swap original ciphertext verifier with a random [`Ciphertext`]
            let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
            let pk = decryption_key.encryption_key();
            let bad_original_ciphertext_verifier = pk.random_ciphertext(&mut rng);
            assert_ne!(
                bad_original_ciphertext_verifier,
                input.original_ciphertext_verifier.clone()
            );
            let bad_input = PiAffgInput::new(
                input.verifier_setup_params,
                input.verifier_encryption_key,
                input.prover_encryption_key,
                &bad_original_ciphertext_verifier,
                input.transformed_ciphertext_verifier,
                input.add_coeff_ciphertext_prover,
                input.mult_coeff_exp,
            );
            assert!(proof
                .clone()
                .verify(bad_input, &(), &mut transcript())
                .is_err());

            // Swap transformed ciphertext verifier with a random [`Ciphertext`]
            let bad_transformed_ciphertext_verifier = pk.random_ciphertext(&mut rng);
            assert_ne!(
                bad_transformed_ciphertext_verifier,
                input.transformed_ciphertext_verifier.clone()
            );
            let bad_input = PiAffgInput::new(
                input.verifier_setup_params,
                input.verifier_encryption_key,
                input.prover_encryption_key,
                input.original_ciphertext_verifier,
                &bad_transformed_ciphertext_verifier,
                input.add_coeff_ciphertext_prover,
                input.mult_coeff_exp,
            );
            assert!(proof
                .clone()
                .verify(bad_input, &(), &mut transcript())
                .is_err());

            // Swap additive coefficient ciphertext prover with a random [`Ciphertext`]
            let bad_add_coeff_ciphertext_prover = pk.random_ciphertext(&mut rng);
            assert_ne!(
                bad_add_coeff_ciphertext_prover,
                input.transformed_ciphertext_verifier.clone()
            );
            let bad_input = PiAffgInput::new(
                input.verifier_setup_params,
                input.verifier_encryption_key,
                input.prover_encryption_key,
                input.original_ciphertext_verifier,
                input.transformed_ciphertext_verifier,
                &bad_add_coeff_ciphertext_prover,
                input.mult_coeff_exp,
            );
            assert!(proof
                .clone()
                .verify(bad_input, &(), &mut transcript())
                .is_err());

            // Swap multi coefficient exponent with a random [`CurvePoint`]
            let mask = random_plusminus_by_size(&mut rng, ELL);
            let bad_mult_coeff_exp = C::GENERATOR.multiply_by_bignum(&mask)?;
            assert_ne!(bad_mult_coeff_exp, input.mult_coeff_exp.clone());
            let bad_input = PiAffgInput::new(
                input.verifier_setup_params,
                input.verifier_encryption_key,
                input.prover_encryption_key,
                input.original_ciphertext_verifier,
                input.transformed_ciphertext_verifier,
                input.add_coeff_ciphertext_prover,
                &bad_mult_coeff_exp,
            );
            assert!(proof.verify(bad_input, &(), &mut transcript()).is_err());
            Ok(())
        };
        with_random_paillier_affg_proof(rng2, &x, &y, f)?;
        Ok(())
    }

    #[test]
    fn piaffg_proof_with_inconsistent_secret_inputs() -> Result<()> {
        let mut rng = init_testing();
        let x = random_plusminus_by_size(&mut rng, ELL);
        let y = random_plusminus_by_size(&mut rng, ELL_PRIME);
        //let rng2 = &mut StdRng::from_seed(rng.gen());
        let (decryption_key_0, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let pk0 = decryption_key_0.encryption_key();

        let (decryption_key_1, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let pk1 = decryption_key_1.encryption_key();

        let mult_coeff_exp = C::GENERATOR.multiply_by_bignum(&x)?;
        let (add_coeff_ciphertext_prover, rho_y) = pk1
            .encrypt(&mut rng, &y)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let original_ciphertext_verifier = pk0.random_ciphertext(&mut rng);

        let (transformed_ciphertext_verifier, rho) = {
            let (transformed_ciphertext_verifier_intermediate, rho) =
                pk0.encrypt(&mut rng, &y).unwrap();
            let transformed_ciphertext_verifier = pk0
                .multiply_and_add(
                    &x,
                    &original_ciphertext_verifier,
                    &transformed_ciphertext_verifier_intermediate,
                )
                .unwrap();
            (transformed_ciphertext_verifier, rho)
        };

        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let input = PiAffgInput::new(
            &setup_params,
            &pk0,
            &pk1,
            &original_ciphertext_verifier,
            &transformed_ciphertext_verifier,
            &add_coeff_ciphertext_prover,
            &mult_coeff_exp,
        );
        let secret = PiAffgSecret::new(&x, &y, &rho, &rho_y);

        // Generate some random elements to use as replacements
        let random_bignumber = random_plusminus(&mut rng, &C::order());
        let random_nonce = Nonce::random(&mut rng, input.prover_encryption_key.modulus());

        // Swap multi coefficient with a random [`BigNumber`]
        assert_ne!(secret.mult_coeff, &random_bignumber);
        let bad_secret = PiAffgSecret::new(&random_bignumber, &y, &rho, &rho_y);
        let bad_proof = PiAffgProof::prove(input, bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

        // Swap add coefficient with a random [`BigNumber`]
        assert_ne!(secret.add_coeff, &random_bignumber);
        let bad_secret = PiAffgSecret::new(&x, &random_bignumber, &rho, &rho_y);
        let bad_proof = PiAffgProof::prove(input, bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

        // Swap add coefficient nonce verifier key with a random [`Nonce`]
        assert_ne!(secret.add_coeff_nonce_verifier_key, &random_nonce);
        let bad_secret = PiAffgSecret::new(&x, &y, &random_nonce, &rho_y);
        let bad_proof = PiAffgProof::prove(input, bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

        // Swap add coefficient nonce prover key with a random [`Nonce`]
        assert_ne!(secret.add_coeff_nonce_prover_key, &random_nonce);
        let bad_secret = PiAffgSecret::new(&x, &y, &rho, &random_nonce);
        let bad_proof = PiAffgProof::prove(input, bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn negative_test_random_proof_elements() -> Result<()> {
        let mut rng = init_testing();
        let x = random_plusminus_by_size(&mut rng, ELL);
        let y = random_plusminus_by_size(&mut rng, ELL_PRIME);
        let rng2 = &mut StdRng::from_seed(rng.gen());

        let f = |proof: PiAffgProof, input: PiAffgInput| {
            let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;

            // Generate some random elements to use as replacements
            let random_mask = random_plusminus_by_size(&mut rng, ELL + EPSILON);
            let scheme = setup_params.scheme();
            let (bad_plaintext_mask, bad_randomness) = scheme.commit(&random_mask, ELL, &mut rng);

            // Swap mult_coeff_commit with a random [`Commitment`]
            let mut bad_proof = proof.clone();
            bad_proof.mult_coeff_commit = bad_plaintext_mask.clone();
            assert_ne!(bad_proof.mult_coeff_commit, proof.mult_coeff_commit);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap add_coeff_commit with a random [`Commitment`]
            let mut bad_proof = proof.clone();
            bad_proof.add_coeff_commit = bad_plaintext_mask.clone();
            assert_ne!(bad_proof.add_coeff_commit, proof.add_coeff_commit);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap random_mult_coeff_commit with a random [`Commitment`]
            let mut bad_proof = proof.clone();
            bad_proof.random_mult_coeff_commit = bad_plaintext_mask.clone();
            assert_ne!(
                bad_proof.random_mult_coeff_commit,
                proof.random_mult_coeff_commit
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap random_add_coeff_commit with a random [`Commitment`]
            let mut bad_proof = proof.clone();
            bad_proof.random_add_coeff_commit = bad_plaintext_mask;
            assert_ne!(
                bad_proof.random_add_coeff_commit,
                proof.random_add_coeff_commit
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap challenge with a random [`Bignumber`]
            let mut bad_proof = proof.clone();
            bad_proof.challenge = random_plusminus(&mut rng, &C::order());
            assert_ne!(bad_proof.challenge, proof.challenge);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap masked_mult_coeff with a random [`Bignumber`]
            let mut bad_proof = proof.clone();
            bad_proof.masked_mult_coeff = random_mask.clone();
            assert_ne!(bad_proof.masked_mult_coeff, proof.masked_mult_coeff);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap masked_add_coeff with a random [`Bignumber`]
            let mut bad_proof = proof.clone();
            bad_proof.masked_add_coeff = random_mask;
            assert_ne!(bad_proof.masked_add_coeff, proof.masked_add_coeff);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap random_affine_ciphertext_verifier with a random [`Ciphertext`]
            let mut bad_proof = proof.clone();
            let plaintext = random_plusminus_by_size(&mut rng, ELL);
            let (ciphertext, _nonce) = input
                .prover_encryption_key
                .encrypt(&mut rng, &plaintext)
                .unwrap();
            bad_proof.random_affine_ciphertext_verifier = ciphertext;
            assert_ne!(
                bad_proof.random_affine_ciphertext_verifier,
                proof.random_affine_ciphertext_verifier
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap random_affine_ciphertext_prover with a random [`Ciphertext`]
            let mut bad_proof = proof.clone();
            let plaintext = random_plusminus_by_size(&mut rng, ELL);
            let (ciphertext, _nonce) = input
                .prover_encryption_key
                .encrypt(&mut rng, &plaintext)
                .unwrap();
            bad_proof.random_add_coeff_ciphertext_prover = ciphertext;
            assert_ne!(
                bad_proof.random_add_coeff_ciphertext_prover,
                proof.random_add_coeff_ciphertext_prover
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap random_mult_coeff_exp with a random [`C`]
            let mut bad_proof = proof.clone();
            let mask = random_plusminus_by_size(&mut rng, ELL);
            bad_proof.random_mult_coeff_exp = C::GENERATOR.multiply_by_bignum(&mask)?;
            assert_ne!(bad_proof.random_mult_coeff_exp, proof.random_mult_coeff_exp);
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap masked_add_coeff_nonce_prover with a random [`MaskedNonce`]
            let mut bad_proof = proof.clone();
            bad_proof.masked_add_coeff_nonce_prover =
                MaskedNonce::random(&mut rng, input.prover_encryption_key.modulus());
            assert_ne!(
                bad_proof.masked_add_coeff_nonce_prover,
                proof.masked_add_coeff_nonce_prover
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap masked_add_coeff_nonce_prover with a random [`MaskedNonce`]
            let mut bad_proof = proof.clone();
            bad_proof.masked_add_coeff_nonce_prover =
                MaskedNonce::random(&mut rng, input.prover_encryption_key.modulus());
            assert_ne!(
                bad_proof.masked_add_coeff_nonce_prover,
                proof.masked_add_coeff_nonce_prover
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap masked_mult_coeff_commit_randomness with a random [`MaskedRandomness`]
            let mut bad_proof = proof.clone();
            bad_proof.masked_mult_coeff_commit_randomness = bad_randomness.as_masked().to_owned();
            assert_ne!(
                bad_proof.masked_mult_coeff_commit_randomness,
                proof.masked_mult_coeff_commit_randomness
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            // Swap masked_add_coeff_commit_randomness with a random [`MaskedRandomness`]
            let mut bad_proof = proof.clone();
            bad_proof.masked_add_coeff_commit_randomness = bad_randomness.as_masked().to_owned();
            assert_ne!(
                bad_proof.masked_add_coeff_commit_randomness,
                proof.masked_add_coeff_commit_randomness
            );
            assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

            Ok(())
        };
        with_random_paillier_affg_proof(rng2, &x, &y, f)?;
        Ok(())
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

        let test_code: TestFn = |proof, input| {
            let result = proof.verify(input, &BadContext {}, &mut transcript());
            assert!(result.is_err());
            Ok(())
        };
        with_random_paillier_affg_proof(&mut rng, &x_small, &y_small, test_code)?;
        Ok(())
    }
}
