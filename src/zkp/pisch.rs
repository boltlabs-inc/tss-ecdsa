// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 22 of <https://eprint.iacr.org/2021/060.pdf>

use super::Proof;
use crate::{
    errors::*,
    messages::{KeygenMessageType, Message, MessageType},
    utils::{self, positive_bn_random_from_transcript},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use utils::CurvePoint;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PiSchProof {
    pub(crate) A: CurvePoint,
    e: BigNumber,
    z: BigNumber,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PiSchPrecommit {
    pub(crate) A: CurvePoint,
    alpha: BigNumber,
}

#[derive(Serialize)]
pub(crate) struct PiSchInput {
    g: CurvePoint,
    q: BigNumber,
    X: CurvePoint,
}

#[derive(Serialize)]
pub(crate) struct PiSchPublicParams {
    g: CurvePoint,
    q: BigNumber,
}

impl PiSchInput {
    pub(crate) fn new(g: &CurvePoint, q: &BigNumber, X: &CurvePoint) -> Self {
        Self {
            g: *g,
            q: q.clone(),
            X: *X,
        }
    }
}

pub(crate) struct PiSchSecret {
    x: BigNumber,
}

impl PiSchSecret {
    pub(crate) fn new(x: &BigNumber) -> Self {
        Self { x: x.clone() }
    }
}

impl Proof for PiSchProof {
    type CommonInput = PiSchInput;
    type ProverSecret = PiSchSecret;

    #[cfg_attr(feature = "flame_it", flame("PiSchProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Sample alpha from F_q
        let alpha = crate::utils::random_positive_bn(rng, &input.q);
        let A = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha)?);

        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(b"A", &serialize!(&A)?);

        // Verifier samples e in F_q
        let e = positive_bn_random_from_transcript(transcript, &input.q);

        let z = &alpha + &e * &secret.x;

        let proof = Self { A, e, z };
        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn verify(&self, input: &Self::CommonInput, transcript: &mut Transcript) -> Result<()> {
        // First check Fiat-Shamir challenge consistency

        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(b"A", &serialize!(&self.A)?);

        // Verifier samples e in F_q
        let e = positive_bn_random_from_transcript(transcript, &input.q);
        if e != self.e {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        // Do equality checks

        let eq_check_1 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z)?);
            let rhs = CurvePoint(self.A.0 + input.X.0 * utils::bn_to_scalar(&self.e)?);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        Ok(())
    }
}

impl PiSchProof {
    pub fn precommit<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &PiSchInput,
    ) -> Result<PiSchPrecommit> {
        // Sample alpha from F_q
        let alpha = crate::utils::random_positive_bn(rng, &input.q);
        let A = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha)?);
        Ok(PiSchPrecommit { A, alpha })
    }

    pub fn prove_from_precommit(
        com: &PiSchPrecommit,
        input: &PiSchInput,
        secret: &PiSchSecret,
        transcript: &Transcript,
    ) -> Result<Self> {
        let A = com.A;
        let mut local_transcript = transcript.clone();
        local_transcript.append_message(b"CommonInput", &serialize!(&input)?);
        local_transcript.append_message(b"A", &serialize!(&A)?);

        // Verifier samples e in F_q
        let e = positive_bn_random_from_transcript(&mut local_transcript, &input.q);

        let z = &com.alpha + &e * &secret.x;

        let proof = Self { A, e, z };
        Ok(proof)
    }
    pub fn verify_with_transcript(
        &self,
        input: &PiSchInput,
        transcript: &Transcript,
    ) -> Result<()> {
        let mut local_transcript = transcript.clone();
        local_transcript.append_message(b"CommonInput", &serialize!(&input)?);
        local_transcript.append_message(b"A", &serialize!(&self.A)?);

        // Verifier samples e in F_q
        let e = positive_bn_random_from_transcript(&mut local_transcript, &input.q);
        if e != self.e {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        // Do equality checks

        let eq_check_1 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z)?);
            let rhs = CurvePoint(self.A.0 + input.X.0 * utils::bn_to_scalar(&self.e)?);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        Ok(())
    }
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Keygen(KeygenMessageType::R3Proof) {
            return Err(InternalError::MisroutedMessage);
        }
        let keygen_decommit: PiSchProof = deserialize!(&message.unverified_bytes)?;
        Ok(keygen_decommit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_schnorr_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        additive: bool,
    ) -> Result<(PiSchInput, PiSchProof)> {
        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);

        let mut x = crate::utils::random_positive_bn(rng, &q);
        let X = CurvePoint(g.0 * utils::bn_to_scalar(&x).unwrap());
        if additive {
            x += crate::utils::random_positive_bn(rng, &q);
        }

        let input = PiSchInput::new(&g, &q, &X);
        let mut transcript = Transcript::new(b"PiSchProof Test");
        let proof = PiSchProof::prove(&input, &PiSchSecret::new(&x), &mut transcript, rng)?;

        Ok((input, proof))
    }

    #[test]
    fn test_schnorr_proof() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();

        let (input, proof) = random_schnorr_proof(&mut rng, false)?;
        let mut transcript = Transcript::new(b"PiSchProof Test");
        proof.verify(&input, &mut transcript)?;

        let (input, proof) = random_schnorr_proof(&mut rng, true)?;
        let mut transcript = Transcript::new(b"PiSchProof Test");
        assert!(proof.verify(&input, &mut transcript).is_err());

        Ok(())
    }

    #[test]
    fn test_precommit_proof() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);

        let x = crate::utils::random_positive_bn(&mut rng, &q);
        let X = CurvePoint(g.0 * utils::bn_to_scalar(&x).unwrap());

        let input = PiSchInput::new(&g, &q, &X);
        let com = PiSchProof::precommit(&mut rng, &input)?;
        let transcript = Transcript::new(b"some external proof stuff");
        let proof =
            PiSchProof::prove_from_precommit(&com, &input, &PiSchSecret::new(&x), &transcript)?;
        proof.verify_with_transcript(&input, &transcript)?;

        //test public param mismatch
        let lambda = crate::utils::random_positive_bn(&mut rng, &q);
        let h = CurvePoint(g.0 * utils::bn_to_scalar(&lambda).unwrap());
        let input2 = PiSchInput::new(&h, &q, &X);
        let proof2 =
            PiSchProof::prove_from_precommit(&com, &input2, &PiSchSecret::new(&x), &transcript)?;
        assert!(proof2.verify_with_transcript(&input, &transcript).is_err());

        //test transcript mismatch
        let transcript2 = Transcript::new(b"some other external proof stuff");
        let proof3 =
            PiSchProof::prove_from_precommit(&com, &input, &PiSchSecret::new(&x), &transcript2)?;
        assert!(proof3.verify_with_transcript(&input, &transcript).is_err());

        Ok(())
    }
}
