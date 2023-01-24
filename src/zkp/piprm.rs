// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 17 of <https://eprint.iacr.org/2021/060.pdf>

use crate::{errors::*, ring_pedersen::RingPedersen, utils::*};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::Proof;

// Soundness parameter lambda.
const LAMBDA: usize = crate::parameters::SOUNDNESS_PARAMETER;

/// Proof of ...
///
/// Each set of values must have length `LAMBDA`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiPrmProof {
    a_values: Vec<BigNumber>,
    e_values: Vec<u8>,
    z_values: Vec<BigNumber>,
}

#[derive(Serialize)]
pub(crate) struct PiPrmInput(RingPedersen);

impl PiPrmInput {
    pub(crate) fn new(ring_pedersen: RingPedersen) -> Self {
        Self(ring_pedersen)
    }
}

pub(crate) struct PiPrmSecret {
    lambda: BigNumber,
    phi_n: BigNumber,
}

impl PiPrmSecret {
    pub(crate) fn new(lambda: &BigNumber, phi_n: &BigNumber) -> Self {
        Self {
            lambda: lambda.clone(),
            phi_n: phi_n.clone(),
        }
    }
}

impl Proof for PiPrmProof {
    type CommonInput = PiPrmInput;
    type ProverSecret = PiPrmSecret;

    // Needs to be the case that s = t^lambda (mod N)
    #[cfg_attr(feature = "flame_it", flame("RingPedersenProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        let secret_a_values: Vec<_> =
            std::iter::repeat_with(|| random_positive_bn(rng, &secret.phi_n))
                .take(LAMBDA)
                .collect();

        let public_a_values = secret_a_values
            .iter()
            .map(|a| modpow(input.0.t(), a, input.0.modulus()))
            .collect::<Vec<_>>();

        let mut transcript = Transcript::new(b"RingPedersenProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(b"A_i values", &serialize!(&public_a_values)?);

        let mut e_values = [0u8; LAMBDA];
        transcript.challenge_bytes(b"e_i values", e_values.as_mut_slice());

        let z_values = e_values
            .iter()
            .zip(secret_a_values)
            .map(|(e, a)| {
                if e % 2 == 1 {
                    a.modadd(&secret.lambda, &secret.phi_n)
                } else {
                    a
                }
            })
            .collect();

        let proof = Self {
            a_values: public_a_values,
            e_values: e_values.into(),
            z_values,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("RingPedersenProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        if self.a_values.len() != LAMBDA
            || self.e_values.len() != LAMBDA
            || self.z_values.len() != LAMBDA
        {
            // Ensure that everything should be the same length LAMBDA
            return verify_err!("Check that everything should be the same length LAMBDA failed");
        }

        let mut transcript = Transcript::new(b"RingPedersenProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(b"A_i values", &serialize!(&self.a_values)?);

        let mut e_values = [0u8; LAMBDA];
        transcript.challenge_bytes(b"e_i values", e_values.as_mut_slice());

        // Check Fiat-Shamir consistency
        if e_values != self.e_values.as_slice() {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        let is_sound = e_values
            .iter()
            .zip(&self.z_values)
            .zip(&self.a_values)
            .map(|((e, z), a)| {
                // Verify that t^z = A * s^e (mod N)
                let lhs = modpow(input.0.t(), z, input.0.modulus());
                let rhs = if e % 2 == 1 {
                    a.modmul(input.0.s(), input.0.modulus())
                } else {
                    a.nmod(input.0.modulus())
                };
                lhs == rhs
            })
            .all(|check| check);

        if !is_sound {
            return verify_err!("Verify that t^z = A * s^e (mod N) check failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::paillier::prime_gen;

    use super::*;

    fn random_ring_pedersen_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(PiPrmInput, PiPrmProof)> {
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(rng).unwrap();
        let N = &p * &q;
        let phi_n = (p - 1) * (q - 1);
        let tau = BigNumber::from_rng(&N, rng);
        let lambda = BigNumber::from_rng(&phi_n, rng);
        let t = modpow(&tau, &BigNumber::from(2), &N);
        let s = modpow(&t, &lambda, &N);

        let ring_pedersen = RingPedersen::from_parts(s, t, N);
        let input = PiPrmInput::new(ring_pedersen);
        let proof = PiPrmProof::prove(rng, &input, &PiPrmSecret::new(&lambda, &phi_n))?;
        Ok((input, proof))
    }

    #[test]
    fn test_ring_pedersen_proof() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
        let (input, proof) = random_ring_pedersen_proof(&mut rng)?;
        proof.verify(&input)?;

        Ok(())
    }

    #[test]
    fn test_ring_pedersen_proof_roundtrip() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
        let (_, proof) = random_ring_pedersen_proof(&mut rng)?;
        let buf = bincode::serialize(&proof).unwrap();
        let orig: PiPrmProof = bincode::deserialize(&buf).unwrap();
        assert_eq!(buf, bincode::serialize(&orig).unwrap());
        Ok(())
    }
}
