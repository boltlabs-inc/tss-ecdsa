// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 15 of <https://eprint.iacr.org/2021/060.pdf>
//!
//! Proves that the prover knows an x and y where X = g^x and y is the
//! plaintext of a Paillier ciphertext

use crate::{
    errors::*,
    paillier::{Ciphertext, EncryptionKey, MaskedNonce, Nonce},
    parameters::{ELL, ELL_PRIME, EPSILON},
    ring_pedersen::{Commitment, MaskedRandomness, VerifiedRingPedersen},
    utils::{self, k256_order, plusminus_bn_random_from_transcript, random_plusminus_by_size},
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiAffgProof {
    alpha: BigNumber,
    beta: BigNumber,
    S: Commitment,
    T: Commitment,
    A: Ciphertext,
    B_x: CurvePoint,
    B_y: Ciphertext,
    E: Commitment,
    F: Commitment,
    e: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    z3: MaskedRandomness,
    z4: MaskedRandomness,
    w: MaskedNonce,
    w_y: MaskedNonce,
}

#[derive(Serialize)]
pub(crate) struct PiAffgInput {
    setup_params: VerifiedRingPedersen,
    g: CurvePoint,
    /// This corresponds to `N_0` in the paper.
    pk0: EncryptionKey,
    /// This corresponds to `N_1` in the paper.
    pk1: EncryptionKey,
    C: Ciphertext,
    D: Ciphertext,
    Y: Ciphertext,
    X: CurvePoint,
}

impl PiAffgInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        setup_params: &VerifiedRingPedersen,
        g: &CurvePoint,
        pk0: &EncryptionKey,
        pk1: &EncryptionKey,
        C: &Ciphertext,
        D: &Ciphertext,
        Y: &Ciphertext,
        X: &CurvePoint,
    ) -> Self {
        Self {
            setup_params: setup_params.clone(),
            g: *g,
            pk0: pk0.clone(),
            pk1: pk1.clone(),
            C: C.clone(),
            D: D.clone(),
            Y: Y.clone(),
            X: *X,
        }
    }
}

#[derive(ZeroizeOnDrop)]
pub(crate) struct PiAffgSecret {
    x: BigNumber,
    y: BigNumber,
    rho: Nonce,
    rho_y: Nonce,
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
    pub(crate) fn new(x: &BigNumber, y: &BigNumber, rho: &Nonce, rho_y: &Nonce) -> Self {
        Self {
            x: x.clone(),
            y: y.clone(),
            rho: rho.clone(),
            rho_y: rho_y.clone(),
        }
    }
}

// Common input is: g, N0, N1, C, D, Y, X
// Prover secrets are: (x, y, rho, rho_y)
//
// (Note that we use ELL = ELL' from the paper)
impl Proof for PiAffgProof {
    type CommonInput = PiAffgInput;
    type ProverSecret = PiAffgSecret;
    // N0: modulus, K: Paillier ciphertext
    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    #[allow(clippy::many_single_char_names)]
    fn prove<R: RngCore + CryptoRng>(
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Sample alpha from 2^{ELL + EPSILON}
        let alpha = random_plusminus_by_size(rng, ELL + EPSILON);
        // Sample beta from 2^{ELL_PRIME + EPSILON}.
        let beta = random_plusminus_by_size(rng, ELL_PRIME + EPSILON);

        let (b, r) = input
            .pk0
            .encrypt(rng, &beta)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let A = input
            .pk0
            .multiply_and_add(&alpha, &input.C, &b)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let B_x = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha)?);
        let (B_y, r_y) = input
            .pk1
            .encrypt(rng, &beta)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let (E, gamma) = input
            .setup_params
            .scheme()
            .commit(&alpha, ELL + EPSILON, rng);
        let (S, m) = input.setup_params.scheme().commit(&secret.x, ELL, rng);
        let (F, delta) = input
            .setup_params
            .scheme()
            .commit(&beta, ELL + EPSILON, rng);
        let (T, mu) = input.setup_params.scheme().commit(&secret.y, ELL, rng);

        Self::fill_transcript(transcript, context, input, &S, &T, &A, &B_x, &B_y, &E, &F)?;

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(transcript, &k256_order());

        let z1 = &alpha + &e * &secret.x;
        let z2 = &beta + &e * &secret.y;
        let z3 = m.mask(&gamma, &e);
        let z4 = mu.mask(&delta, &e);
        let w = input.pk0.mask(&secret.rho, &r, &e);
        let w_y = input.pk1.mask(&secret.rho_y, &r_y, &e);

        let proof = Self {
            alpha,
            beta,
            S,
            T,
            A,
            B_x,
            B_y,
            E,
            F,
            e,
            z1,
            z2,
            z3,
            z4,
            w,
            w_y,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    fn verify(
        &self,
        input: &Self::CommonInput,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        Self::fill_transcript(
            transcript, context, input, &self.S, &self.T, &self.A, &self.B_x, &self.B_y, &self.E,
            &self.F,
        )?;
        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(transcript, &k256_order());

        if e != self.e {
            warn!("Fiat-Shamir consistency check failed");
            return Err(InternalError::ProtocolError);
        }

        // Do equality checks

        let eq_check_1 = {
            let a = input
                .pk0
                .encrypt_with_nonce(&self.z2, &self.w)
                .map_err(|_| InternalError::ProtocolError)?;
            let lhs = input
                .pk0
                .multiply_and_add(&self.z1, &input.C, &a)
                .map_err(|_| InternalError::ProtocolError)?;
            let rhs = input
                .pk0
                .multiply_and_add(&self.e, &input.D, &self.A)
                .map_err(|_| InternalError::ProtocolError)?;
            lhs == rhs
        };
        if !eq_check_1 {
            warn!("eq_check_1 failed");
            return Err(InternalError::ProtocolError);
        }

        let eq_check_2 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z1)?);
            let rhs = CurvePoint(self.B_x.0 + input.X.0 * utils::bn_to_scalar(&self.e)?);
            lhs == rhs
        };
        if !eq_check_2 {
            warn!("eq_check_2 failed");
            return Err(InternalError::ProtocolError);
        }

        let eq_check_3 = {
            let lhs = input
                .pk1
                .encrypt_with_nonce(&self.z2, &self.w_y)
                .map_err(|_| InternalError::ProtocolError)?;

            let rhs = input
                .pk1
                .multiply_and_add(&self.e, &input.Y, &self.B_y)
                .map_err(|_| InternalError::ProtocolError)?;
            lhs == rhs
        };
        if !eq_check_3 {
            warn!("eq_check_3 failed");
            return Err(InternalError::ProtocolError);
        }

        let eq_check_4 = {
            let lhs = input.setup_params.scheme().reconstruct(&self.z1, &self.z3);
            let rhs = input
                .setup_params
                .scheme()
                .combine(&self.E, &self.S, &self.e);
            lhs == rhs
        };
        if !eq_check_4 {
            warn!("eq_check_4 failed");
            return Err(InternalError::ProtocolError);
        }

        let eq_check_5 = {
            let lhs = input.setup_params.scheme().reconstruct(&self.z2, &self.z4);
            let rhs = input
                .setup_params
                .scheme()
                .combine(&self.F, &self.T, &self.e);
            lhs == rhs
        };
        if !eq_check_5 {
            warn!("eq_check_5 failed");
            return Err(InternalError::ProtocolError);
        }

        // Do range check

        let ell_bound = BigNumber::one() << (ELL + EPSILON);
        let ell_prime_bound = BigNumber::one() << (ELL_PRIME + EPSILON);
        if self.z1 < -ell_bound.clone() || self.z1 > ell_bound {
            warn!("self.z1 > ell_bound check failed");
            return Err(InternalError::ProtocolError);
        }
        if self.z2 < -ell_prime_bound.clone() || self.z2 > ell_prime_bound {
            warn!("self.z2 > ell_prime_bound check failed");
            return Err(InternalError::ProtocolError);
        }

        Ok(())
    }
}

impl PiAffgProof {
    #[allow(clippy::too_many_arguments)]
    fn fill_transcript(
        transcript: &mut Transcript,
        context: &impl ProofContext,
        input: &PiAffgInput,
        S: &Commitment,
        T: &Commitment,
        A: &Ciphertext,
        B_x: &CurvePoint,
        B_y: &Ciphertext,
        E: &Commitment,
        F: &Commitment,
    ) -> Result<()> {
        // First, do Fiat-Shamir consistency check
        transcript.append_message(b"PiAffg ProofContext", &context.as_bytes()?);
        transcript.append_message(b"PiAffg CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, T, A, B_x, B_y, E, F)",
            &[
                S.to_bytes(),
                T.to_bytes(),
                A.to_bytes(),
                serialize!(&B_x).unwrap(),
                B_y.to_bytes(),
                E.to_bytes(),
                F.to_bytes(),
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

        let g = k256::ProjectivePoint::GENERATOR;

        let X = CurvePoint(g * utils::bn_to_scalar(x)?);
        let (Y, rho_y) = pk1.encrypt(rng, y).unwrap();

        let C = pk0.random_ciphertext(rng);

        // Compute D = C^x * (1 + N0)^y rho^N0 (mod N0^2)
        let (D, rho) = {
            let (D_intermediate, rho) = pk0.encrypt(rng, y).unwrap();
            let D = pk0.multiply_and_add(x, &C, &D_intermediate).unwrap();
            (D, rho)
        };

        let setup_params = VerifiedRingPedersen::gen(rng, &())?;
        let mut transcript = Transcript::new(b"random_paillier_affg_proof");
        let input = PiAffgInput::new(&setup_params, &CurvePoint(g), &pk0, &pk1, &C, &D, &Y, &X);

        let proof = PiAffgProof::prove(
            &input,
            &PiAffgSecret::new(x, y, &rho, &rho_y),
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
