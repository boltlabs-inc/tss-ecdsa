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

use super::Proof;
use crate::{
    errors::*,
    paillier::{MaskedNonce, PaillierNonce},
    paillier::{PaillierCiphertext, PaillierEncryptionKey},
    parameters::{ELL, ELL_PRIME, EPSILON},
    utils::{
        self, k256_order, modpow, plusminus_bn_random_from_transcript, random_plusminus,
        random_plusminus_by_size,
    },
    zkp::setup::ZkSetupParameters,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use utils::CurvePoint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiAffgProof {
    alpha: BigNumber,
    beta: BigNumber,
    S: BigNumber,
    T: BigNumber,
    A: PaillierCiphertext,
    B_x: CurvePoint,
    B_y: PaillierCiphertext,
    E: BigNumber,
    F: BigNumber,
    e: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    z3: BigNumber,
    z4: BigNumber,
    w: MaskedNonce,
    w_y: MaskedNonce,
}

#[derive(Serialize)]
pub(crate) struct PiAffgInput {
    setup_params: ZkSetupParameters,
    g: CurvePoint,
    /// This corresponds to `N_0` in the paper.
    pk0: PaillierEncryptionKey,
    /// This corresponds to `N_1` in the paper.
    pk1: PaillierEncryptionKey,
    C: PaillierCiphertext,
    D: PaillierCiphertext,
    Y: PaillierCiphertext,
    X: CurvePoint,
}

impl PiAffgInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        setup_params: &ZkSetupParameters,
        g: &CurvePoint,
        pk0: &PaillierEncryptionKey,
        pk1: &PaillierEncryptionKey,
        C: &PaillierCiphertext,
        D: &PaillierCiphertext,
        Y: &PaillierCiphertext,
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

pub(crate) struct PiAffgSecret {
    x: BigNumber,
    y: BigNumber,
    rho: PaillierNonce,
    rho_y: PaillierNonce,
}

impl PiAffgSecret {
    pub(crate) fn new(
        x: &BigNumber,
        y: &BigNumber,
        rho: &PaillierNonce,
        rho_y: &PaillierNonce,
    ) -> Self {
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
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // Sample alpha from 2^{ELL + EPSILON}
        let alpha = random_plusminus_by_size(rng, ELL + EPSILON);
        // Sample beta from 2^{ELL_PRIME + EPSILON}.
        let beta = random_plusminus_by_size(rng, ELL_PRIME + EPSILON);

        // range_ell_eps = 2^{ELL + EPSILON} * N_hat
        let range_ell_eps = (BigNumber::one() << (ELL + EPSILON)) * &input.setup_params.N;
        let gamma = random_plusminus(rng, &range_ell_eps);
        let delta = random_plusminus(rng, &range_ell_eps);

        // range_ell = 2^ELL * N_hat
        let range_ell = (BigNumber::one() << ELL) * &input.setup_params.N;
        let m = random_plusminus(rng, &range_ell);
        let mu = random_plusminus(rng, &range_ell);

        let (b, r) = input.pk0.encrypt(rng, &beta)?;
        let A = input.pk0.multiply_and_add(&alpha, &input.C, &b)?;
        let B_x = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha)?);
        let (B_y, r_y) = input.pk1.encrypt(rng, &beta)?;
        let E = {
            let a = modpow(&input.setup_params.s, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &gamma, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let S = {
            let a = modpow(&input.setup_params.s, &secret.x, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &m, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let F = {
            let a = modpow(&input.setup_params.s, &beta, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &delta, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let T = {
            let a = modpow(&input.setup_params.s, &secret.y, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &mu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };

        let mut transcript = Transcript::new(b"PiAffgProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, T, A, B_x, B_y, E, F)",
            &[
                S.to_bytes(),
                T.to_bytes(),
                A.to_bytes(),
                serialize!(&B_x)?,
                B_y.to_bytes(),
                E.to_bytes(),
                F.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &k256_order());

        let z1 = &alpha + &e * &secret.x;
        let z2 = &beta + &e * &secret.y;
        let z3 = gamma + &e * m;
        let z4 = delta + &e * mu;
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
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // First, do Fiat-Shamir consistency check

        let mut transcript = Transcript::new(b"PiAffgProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, T, A, B_x, B_y, E, F)",
            &[
                self.S.to_bytes(),
                self.T.to_bytes(),
                self.A.to_bytes(),
                serialize!(&self.B_x)?,
                self.B_y.to_bytes(),
                self.E.to_bytes(),
                self.F.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &k256_order());

        if e != self.e {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        let N0_squared = input.pk0.n() * input.pk0.n();
        let N1_squared = input.pk1.n() * input.pk1.n();

        // Do equality checks

        let eq_check_1 = {
            let a = modpow(&input.C.0, &self.z1, &N0_squared);
            let b = modpow(&(BigNumber::one() + input.pk0.n()), &self.z2, &N0_squared);
            let c = modpow(&self.w.0, input.pk0.n(), &N0_squared);
            let lhs = PaillierCiphertext(a.modmul(&b, &N0_squared).modmul(&c, &N0_squared));
            let rhs = input.pk0.multiply_and_add(&self.e, &input.D, &self.A)?;
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z1)?);
            let rhs = CurvePoint(self.B_x.0 + input.X.0 * utils::bn_to_scalar(&self.e)?);
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let a = modpow(&(BigNumber::one() + input.pk1.n()), &self.z2, &N1_squared);
            let b = modpow(&self.w_y.0, input.pk1.n(), &N1_squared);
            let lhs = PaillierCiphertext(a.modmul(&b, &N1_squared));
            let rhs = input.pk1.multiply_and_add(&self.e, &input.Y, &self.B_y)?;
            lhs == rhs
        };
        if !eq_check_3 {
            return verify_err!("eq_check_3 failed");
        }

        let eq_check_4 = {
            let a = modpow(&input.setup_params.s, &self.z1, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z3, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.E.modmul(
                &modpow(&self.S, &self.e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_4 {
            return verify_err!("eq_check_4 failed");
        }

        let eq_check_5 = {
            let a = modpow(&input.setup_params.s, &self.z2, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z4, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.F.modmul(
                &modpow(&self.T, &self.e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_5 {
            return verify_err!("eq_check_5 failed");
        }

        // Do range check

        let ell_bound = BigNumber::one() << (ELL + EPSILON);
        let ell_prime_bound = BigNumber::one() << (ELL_PRIME + EPSILON);
        if self.z1 < -ell_bound.clone() || self.z1 > ell_bound {
            return verify_err!("self.z1 > ell_bound check failed");
        }
        if self.z2 < -ell_prime_bound.clone() || self.z2 > ell_prime_bound {
            return verify_err!("self.z2 > ell_prime_bound check failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{paillier::PaillierDecryptionKey, utils::random_plusminus_by_size_with_minimum};

    fn random_paillier_affg_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
        y: &BigNumber,
    ) -> Result<()> {
        let (decryption_key_0, p0, q0) = PaillierDecryptionKey::new(rng)?;
        let N0 = &p0 * &q0;
        let pk0 = decryption_key_0.encryption_key();

        let (decryption_key_1, _, _) = PaillierDecryptionKey::new(rng)?;
        let pk1 = decryption_key_1.encryption_key();

        let g = k256::ProjectivePoint::GENERATOR;

        let X = CurvePoint(g * utils::bn_to_scalar(x).unwrap());
        let (Y, rho_y) = pk1.encrypt(rng, y)?;

        let N0_squared = &N0 * &N0;
        let C = PaillierCiphertext(crate::utils::random_positive_bn(rng, &N0_squared));

        // Compute D = C^x * (1 + N0)^y rho^N0 (mod N0^2)
        let (D, rho) = {
            let (D_intermediate, rho) = pk0.encrypt(rng, y)?;
            let D = pk0.multiply_and_add(x, &C, &D_intermediate)?;
            (D, rho)
        };

        let setup_params = ZkSetupParameters::gen(rng)?;

        let input = PiAffgInput::new(&setup_params, &CurvePoint(g), &pk0, &pk1, &C, &D, &Y, &X);
        let proof = PiAffgProof::prove(rng, &input, &PiAffgSecret::new(x, y, &rho, &rho_y))?;

        proof.verify(&input)
    }

    #[test]
    fn test_paillier_affg_proof() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();

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
        random_paillier_affg_proof(&mut rng, &x_small, &y_small)?;

        // All other combinations should fail
        assert!(random_paillier_affg_proof(&mut rng, &x_small, &y_large).is_err());
        assert!(random_paillier_affg_proof(&mut rng, &x_large, &y_small).is_err());
        assert!(random_paillier_affg_proof(&mut rng, &x_large, &y_large).is_err());

        Ok(())
    }
}
