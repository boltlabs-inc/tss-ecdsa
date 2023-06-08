// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 22 of <https://eprint.iacr.org/2021/060.pdf>

use crate::{
    errors::*,
    messages::{KeygenMessageType, Message, MessageType},
    utils::{self, k256_order, positive_challenge_from_transcript},
    zkp::{Proof2, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, ops::Deref};
use tracing::error;
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

/// Common input and setup parameters known to both the prover and verifier.
///
/// TODO: Copying/Cloning references is harmless and sometimes necessary. So we
/// implement Clone and Copy for this type.
#[derive(Serialize, Clone)]
pub(crate) struct PiSchInput<'a> {
    g: CurvePoint,
    q: BigNumber,
    X: &'a CurvePoint,
}

#[derive(Serialize)]
pub(crate) struct PiSchPublicParams {
    g: CurvePoint,
    q: BigNumber,
}

impl<'a> PiSchInput<'a> {
    pub(crate) fn new(X: &'a CurvePoint) -> PiSchInput<'a> {
        Self {
            g: CurvePoint(k256::ProjectivePoint::GENERATOR),
            q: k256_order(),
            X,
        }
    }
}

impl AsRef<CurvePoint> for PiSchInput<'_> {
    fn as_ref(&self) -> &CurvePoint {
        self.X
    }
}

pub(crate) struct PiSchSecret<'a> {
    x: &'a BigNumber,
}

impl<'a> Debug for PiSchSecret<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("pisch::PiSchSecret")
            .field("x", &"[redacted]")
            .finish()
    }
}

impl<'a> PiSchSecret<'a> {
    pub(crate) fn new(x: &'a BigNumber) -> PiSchSecret<'a> {
        Self { x }
    }
}

impl AsRef<BigNumber> for PiSchSecret<'_> {
    fn as_ref(&self) -> &BigNumber {
        self.x
    }
}

impl<'a> Deref for PiSchSecret<'a> {
    type Target = BigNumber;

    fn deref(&self) -> &Self::Target {
        self.x
    }
}
// pub(crate) struct PiSchInputBuilder {
//     X: CurvePoint,
// }
//
// impl PiSchInputBuilder {
//     pub(crate) fn new(X: CurvePoint) -> Self {
//         PiSchInputBuilder { X }
//     }
//
//     pub(crate) fn build(self) -> PiSchInput {
//         PiSchInput { X: self.X }
//     }
// }

impl Proof2 for PiSchProof {
    type CommonInput<'a> = PiSchInput<'a>;
    type ProverSecret<'a> = PiSchSecret<'a>;
    #[cfg_attr(feature = "flame_it", flame("PiSchProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: Self::CommonInput<'_>,
        secret: Self::ProverSecret<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Sample alpha from F_q
        let alpha = crate::utils::random_positive_bn(rng, &k256_order());
        let A = CurvePoint(CurvePoint::GENERATOR.0 * utils::bn_to_scalar(&alpha)?);

        Self::fill_transcript(transcript, context, &input, &A)?;

        // Verifier samples e in F_q
        let e = positive_challenge_from_transcript(transcript, &k256_order())?;

        let z = &alpha + &e * secret.x;

        let proof = Self { A, e, z };
        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiSchProof"))]
    fn verify(
        self,
        input: Self::CommonInput<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        // First check Fiat-Shamir challenge consistency
        Self::fill_transcript(transcript, context, &input, &self.A)?;

        // Verifier samples e in F_q
        let e = positive_challenge_from_transcript(transcript, &k256_order())?;
        if e != self.e {
            error!("Fiat-Shamir consistency check failed");
            return Err(InternalError::ProtocolError);
        }

        // Do equality checks

        let eq_check_1 = {
            let lhs = CurvePoint(CurvePoint::GENERATOR.0 * utils::bn_to_scalar(&self.z)?);
            let rhs = CurvePoint(self.A.0 + input.X.0 * utils::bn_to_scalar(&self.e)?);
            lhs == rhs
        };
        if !eq_check_1 {
            error!("eq_check_1 failed");
            return Err(InternalError::ProtocolError);
        }

        Ok(())
    }
}

impl PiSchProof {
    pub fn precommit<R: RngCore + CryptoRng>(
        rng: &mut R,
        _input: &PiSchInput,
    ) -> Result<PiSchPrecommit> {
        // Sample alpha from F_q
        let alpha = crate::utils::random_positive_bn(rng, &k256_order());
        let A = CurvePoint(CurvePoint::GENERATOR.0 * utils::bn_to_scalar(&alpha)?);
        Ok(PiSchPrecommit { A, alpha })
    }

    pub fn prove_from_precommit(
        context: &impl ProofContext,
        com: &PiSchPrecommit,
        input: &PiSchInput,
        secret: &PiSchSecret,
        transcript: &Transcript,
    ) -> Result<Self> {
        let A = com.A;
        let mut local_transcript = transcript.clone();

        Self::fill_transcript(&mut local_transcript, context, input, &A)?;

        // Verifier samples e in F_q
        let e = positive_challenge_from_transcript(&mut local_transcript, &k256_order())?;

        let z = &com.alpha + &e * secret.x;

        let proof = Self { A, e, z };
        Ok(proof)
    }
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Keygen(KeygenMessageType::R3Proof))?;
        let keygen_decommit: PiSchProof = deserialize!(&message.unverified_bytes)?;
        Ok(keygen_decommit)
    }
    fn fill_transcript(
        transcript: &mut Transcript,
        context: &impl ProofContext,
        input: &PiSchInput,
        A: &CurvePoint,
    ) -> Result<()> {
        transcript.append_message(b"PiSch ProofContext", &context.as_bytes()?);
        transcript.append_message(b"PiSch CommonInput", &serialize!(&input)?);
        transcript.append_message(b"A", &serialize!(A)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utils::testing::init_testing, zkp::BadContext};
    fn transcript() -> Transcript {
        Transcript::new(b"PiSchProof Test")
    }

    type TestFn = fn(PiSchProof, PiSchInput) -> Result<()>;

    fn with_random_schnorr_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        additive: bool,
        test_code: impl Fn(PiSchProof, PiSchInput) -> Result<()>,
    ) -> Result<()> {
        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);

        let mut x = crate::utils::random_positive_bn(rng, &q);
        let X = CurvePoint(g.0 * utils::bn_to_scalar(&x).unwrap());
        if additive {
            x += crate::utils::random_positive_bn(rng, &q);
        }

        let input = PiSchInput::new(&X);
        let proof = PiSchProof::prove(
            input.clone(),
            PiSchSecret::new(&x),
            &(),
            &mut transcript(),
            rng,
        )?;

        test_code(proof, input)?;
        Ok(())
    }

    #[test]
    fn test_schnorr_proof() -> Result<()> {
        let mut rng = init_testing();

        let test_code: TestFn = |proof, input| {
            proof.verify(input, &(), &mut transcript())?;
            Ok(())
        };
        with_random_schnorr_proof(&mut rng, false, test_code)?;

        let test_code: TestFn = |proof, input| {
            assert!(proof.verify(input, &(), &mut transcript()).is_err());
            Ok(())
        };
        with_random_schnorr_proof(&mut rng, true, test_code)?;

        Ok(())
    }

    #[test]
    fn pisch_proof_context_must_be_correct() -> Result<()> {
        let mut rng = init_testing();

        let test_code: TestFn = |proof, input| {
            let result = proof.verify(input, &BadContext {}, &mut transcript());
            assert!(result.is_err());
            Ok(())
        };

        with_random_schnorr_proof(&mut rng, false, test_code)?;
        Ok(())
    }

    #[test]
    fn test_precommit_proof() -> Result<()> {
        let mut rng = init_testing();

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);

        let x = crate::utils::random_positive_bn(&mut rng, &q);
        let X = CurvePoint(g.0 * utils::bn_to_scalar(&x).unwrap());

        let input = PiSchInput::new(&X);
        let com = PiSchProof::precommit(&mut rng, &input)?;
        let mut transcript = Transcript::new(b"some external proof stuff");
        let proof = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &PiSchSecret::new(&x),
            &transcript,
        )?;
        proof.verify(input.clone(), &(), &mut transcript)?;

        //test public param mismatch
        // let lambda = crate::utils::random_positive_bn(&mut rng, &q);
        // let h = CurvePoint(g.0 * utils::bn_to_scalar(&lambda).unwrap());
        let input2 = PiSchInput::new(&X);
        let proof2 = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input2,
            &PiSchSecret::new(&x),
            &transcript,
        )?;
        assert!(proof2.verify(input.clone(), &(), &mut transcript).is_err());

        //test transcript mismatch
        let transcript2 = Transcript::new(b"some other external proof stuff");
        let proof3 = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &PiSchSecret::new(&x),
            &transcript2,
        )?;
        assert!(proof3.verify(input, &(), &mut transcript).is_err());

        Ok(())
    }
}
