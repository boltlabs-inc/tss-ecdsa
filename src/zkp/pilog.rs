// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 25 of <https://eprint.iacr.org/2021/060.pdf>

use super::Proof;
use crate::{
    errors::*,
    paillier::{MaskedNonce, PaillierNonce},
    paillier::{PaillierCiphertext, PaillierEncryptionKey},
    parameters::{ELL, EPSILON},
    utils::{
        self, modpow, plusminus_bn_random_from_transcript, random_plusminus_by_size,
        random_plusminus_scaled,
    },
    zkp::setup::ZkSetupParameters,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use utils::CurvePoint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiLogProof {
    alpha: BigNumber,
    S: BigNumber,
    A: PaillierCiphertext,
    Y: CurvePoint,
    D: BigNumber,
    e: BigNumber,
    z1: BigNumber,
    z2: MaskedNonce,
    z3: BigNumber,
}

#[derive(Serialize)]
pub(crate) struct PiLogInput {
    setup_params: ZkSetupParameters,
    q: BigNumber,
    /// This corresponds to `N_0` in the paper.
    pk: PaillierEncryptionKey,
    C: PaillierCiphertext,
    X: CurvePoint,
    g: CurvePoint,
}

impl PiLogInput {
    pub(crate) fn new(
        setup_params: &ZkSetupParameters,
        q: &BigNumber,
        pk: &PaillierEncryptionKey,
        C: &PaillierCiphertext,
        X: &CurvePoint,
        g: &CurvePoint,
    ) -> Self {
        Self {
            setup_params: setup_params.clone(),
            q: q.clone(),
            pk: pk.clone(),
            C: C.clone(),
            X: *X,
            g: *g,
        }
    }
}

pub(crate) struct PiLogSecret {
    x: BigNumber,
    rho: PaillierNonce,
}

impl PiLogSecret {
    pub(crate) fn new(x: &BigNumber, rho: &PaillierNonce) -> Self {
        Self {
            x: x.clone(),
            rho: rho.clone(),
        }
    }
}

// Common input is: q, N0, C, X, g
// Prover secrets are: (x, rho)
impl Proof for PiLogProof {
    type CommonInput = PiLogInput;
    type ProverSecret = PiLogSecret;

    // N0: modulus, K: Paillier ciphertext
    #[cfg_attr(feature = "flame_it", flame("PiLogProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // Sample alpha from plus/minus 2^{ELL + EPSILON}
        let alpha = random_plusminus_by_size(rng, ELL + EPSILON);

        // range = 2^{ELL} * N_hat
        let mu = random_plusminus_scaled(rng, ELL, &input.setup_params.N);

        // range = 2^{ELL+EPSILON} * N_hat
        let gamma = random_plusminus_scaled(rng, ELL + EPSILON, &input.setup_params.N);

        let S = {
            let a = modpow(&input.setup_params.s, &secret.x, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &mu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let (A, r) = input.pk.encrypt(rng, &alpha)?;
        let Y = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha)?);
        let D = {
            let a = modpow(&input.setup_params.s, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &gamma, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };

        let mut transcript = Transcript::new(b"PiLogProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, A, Y, D)",
            &[S.to_bytes(), A.to_bytes(), serialize!(&Y)?, D.to_bytes()].concat(),
        );

        // Verifier samples from e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &input.q);

        let z1 = &alpha + &e * &secret.x;
        let z2 = input.pk.mask(&secret.rho, &r, &e);
        let z3 = gamma + &e * mu;

        let proof = Self {
            alpha,
            S,
            A,
            Y,
            D,
            e,
            z1,
            z2,
            z3,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiLogProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // First, do Fiat-Shamir consistency check
        let mut transcript = Transcript::new(b"PiLogProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, A, Y, D)",
            &[
                self.S.to_bytes(),
                self.A.to_bytes(),
                serialize!(&self.Y)?,
                self.D.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples from e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &input.q);

        if e != self.e {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        // Do equality checks

        let eq_check_1 = {
            let lhs = input.pk.encrypt_with_nonce(&self.z1, &self.z2)?;
            let rhs = input.pk.multiply_and_add(&self.e, &input.C, &self.A)?;
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z1)?);
            let rhs = CurvePoint(self.Y.0 + input.X.0 * utils::bn_to_scalar(&self.e)?);
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let a = modpow(&input.setup_params.s, &self.z1, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z3, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.D.modmul(
                &modpow(&self.S, &self.e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_3 {
            return verify_err!("eq_check_4 failed");
        }

        // Do range check

        let bound = BigNumber::one() << (ELL + EPSILON);
        if self.z1 < -bound.clone() || self.z1 > bound {
            return verify_err!("self.z1 > bound check failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{paillier::PaillierDecryptionKey, utils::random_plusminus_by_size_with_minimum};

    fn random_paillier_log_proof<R: RngCore + CryptoRng>(rng: &mut R, x: &BigNumber) -> Result<()> {
        let (decryption_key, _, _) = PaillierDecryptionKey::new(rng)?;
        let pk = decryption_key.encryption_key();

        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);

        let X = CurvePoint(g.0 * utils::bn_to_scalar(x).unwrap());
        let (C, rho) = pk.encrypt(rng, x)?;

        let setup_params = ZkSetupParameters::gen(rng)?;

        let input = PiLogInput::new(&setup_params, &crate::utils::k256_order(), &pk, &C, &X, &g);

        let proof = PiLogProof::prove(rng, &input, &PiLogSecret::new(x, &rho))?;

        proof.verify(&input)
    }

    #[test]
    fn test_paillier_log_proof() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();

        let x_small = random_plusminus_by_size(&mut rng, ELL);
        let x_large =
            random_plusminus_by_size_with_minimum(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;

        // Sampling x in the range 2^ELL should always succeed
        random_paillier_log_proof(&mut rng, &x_small)?;

        // Sampling x in the range (2^{ELL + EPSILON}, 2^{ELL + EPSILON + 1}] should
        // fail
        assert!(random_paillier_log_proof(&mut rng, &x_large).is_err());

        Ok(())
    }
}
