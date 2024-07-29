// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof of knowledge of discrete logarithm.
//!
//! More precisely, this module includes methods to create and verify a
//! non-interactive zero-knowledge proof of knowledge of the discrete logarithm
//! `x` of a group element `X` - `x` such that `X = g^x` for a known generator
//! `g`. This is known as Schnorr's identification protocol.
//!
//! This implementation uses a standard Fiat-Shamir transformation to make the
//! proof non-interactive. We only implement it for the group defined by the
//! elliptic curve [secp256k1](https://en.bitcoin.it/wiki/Secp256k1). Although, this proof is a little different from
//! the rest of the proofs in this library as it is not completely
//! non-interactive. It is not a full-on interactive sigma proof because the
//! commitment is not supplied by the verifier, so we do use Fiat-Shamir. But it
//! allows the caller to do the commitment phase without forming the whole proof
//! and send it to the verifier in advance. The proof is defined in Figure 22 of
//! CGGMP[^cite].
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! [EPrint archive, 2021](https://eprint.iacr.org/2021/060.pdf).
use crate::{
    errors::*,
    messages::{KeygenMessageType, KeyrefreshMessageType, Message, MessageType, TshareMessageType},
    utils::{self, k256_order, positive_challenge_from_transcript, random_positive_bn},
    zkp::{Proof, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{convert::AsRef, fmt::Debug};
use tracing::error;
use utils::CurvePoint;

/// Proof of knowledge of discrete logarithm of a group element which is the
/// commitment to the secret.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PiSchProof {
    /// Commitment to the secret (`A` in the paper).
    commitment: CurvePoint,
    /// Fiat-Shamir challenge (`e` in the paper).
    challenge: BigNumber,
    /// Response binding the commitment randomness used in the commitment (`z`
    /// in the paper).
    response: BigNumber,
}

/// Commitment to the mask selected in the commitment phase of the proof.
///
/// Implementation note: this type includes the mask itself. This is for
/// convenience; the mask must not be sent to the verifier at any point as this
/// breaks the security of the proof.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PiSchPrecommit {
    /// Precommitment value (`A` in the paper).
    precommitment: CurvePoint,
    /// Randomness mask for commitment (`alpha` in the paper).
    randomness_for_commitment: BigNumber,
}

/// Common input and setup parameters known to both the prover and verifier.
///
/// Copying/Cloning references is harmless and sometimes necessary. So we
/// implement Clone and Copy for this type.
#[derive(Serialize, Copy, Clone)]
pub(crate) struct CommonInput<'a> {
    x_commitment: &'a CurvePoint,
}

impl PiSchPrecommit {
    pub(crate) fn precommitment(&self) -> &CurvePoint {
        &self.precommitment
    }
}

impl<'a> CommonInput<'a> {
    pub(crate) fn new(x_commitment: &'a impl AsRef<CurvePoint>) -> CommonInput<'a> {
        Self {
            x_commitment: x_commitment.as_ref(),
        }
    }
}

pub(crate) struct ProverSecret<'a> {
    discrete_logarithm: &'a BigNumber,
}

impl<'a> Debug for ProverSecret<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("pisch::PiSchSecret")
            .field("x", &"[redacted]")
            .finish()
    }
}

impl<'a> ProverSecret<'a> {
    pub(crate) fn new(x: &'a BigNumber) -> ProverSecret<'a> {
        Self {
            discrete_logarithm: x,
        }
    }
}

impl Proof for PiSchProof {
    type CommonInput<'a> = CommonInput<'a>;
    type ProverSecret<'a> = ProverSecret<'a>;
    #[cfg_attr(feature = "flame_it", flame("PiSchProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: Self::CommonInput<'_>,
        secret: Self::ProverSecret<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        let com = PiSchProof::precommit(rng)?;
        let proof = PiSchProof::prove_from_precommit(context, &com, &input, &secret, transcript)?;
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
        Self::fill_transcript(transcript, context, &input, &self.commitment)?;

        // Verifier samples e in F_q
        let challenge = positive_challenge_from_transcript(transcript, &k256_order())?;
        if challenge != self.challenge {
            error!("Fiat-Shamir consistency check failed");
            return Err(InternalError::ProtocolError(None));
        }

        // Do equality checks

        let response_matches_commitment = {
            let lhs = CurvePoint::GENERATOR.multiply_by_bignum(&self.response)?;
            let rhs = self.commitment + input.x_commitment.multiply_by_bignum(&self.challenge)?;
            lhs == rhs
        };
        if !response_matches_commitment {
            error!("verification equation checked failed");
            return Err(InternalError::ProtocolError(None));
        }

        Ok(())
    }
}

impl PiSchProof {
    /// "Commitment" phase of the PiSch proof.
    pub fn precommit<R: RngCore + CryptoRng>(rng: &mut R) -> Result<PiSchPrecommit> {
        // Sample alpha from F_q
        let randomness_for_commitment = random_positive_bn(rng, &k256_order());
        // Form a commitment to the mask
        let precommitment = CurvePoint::GENERATOR.multiply_by_bignum(&randomness_for_commitment)?;
        Ok(PiSchPrecommit {
            precommitment,
            randomness_for_commitment,
        })
    }

    /// "Challenge" and "Response" phases of the PiSch proof.
    pub fn prove_from_precommit(
        context: &impl ProofContext,
        com: &PiSchPrecommit,
        input: &CommonInput,
        secret: &ProverSecret,
        transcript: &Transcript,
    ) -> Result<Self> {
        let commitment = com.precommitment;
        let mut local_transcript = transcript.clone();

        Self::fill_transcript(&mut local_transcript, context, input, &commitment)?;

        // Verifier samples e in F_q
        let challenge = positive_challenge_from_transcript(&mut local_transcript, &k256_order())?;

        // Create a response by masking the secret with the challenge and mask
        let response = com.randomness_for_commitment.modadd(
            &challenge.modmul(secret.discrete_logarithm, &k256_order()),
            &k256_order(),
        );

        // Proof consists of all 3 messages in the 3 rounds
        let proof = Self {
            commitment,
            challenge,
            response,
        };
        Ok(proof)
    }

    /// Verify that the proof is valid and that it matches a precommitment.
    pub fn verify_with_precommit(
        self,
        input: CommonInput,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        commitment: &CurvePoint,
    ) -> Result<()> {
        if commitment != &self.commitment {
            error!("the proof does not match the previous commitment");
            return Err(InternalError::ProtocolError(None));
        }
        Self::verify(self, input, context, transcript)
    }

    // Deserialize multiple proofs from a single message.
    pub(crate) fn from_message_multi(message: &Message) -> Result<Vec<Self>> {
        message.check_one_of_type(&[
            MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs),
            MessageType::Tshare(TshareMessageType::R3Proofs),
        ])?;

        let pisch_proofs: Vec<PiSchProof> = deserialize!(&message.unverified_bytes)?;
        for pisch_proof in &pisch_proofs {
            if pisch_proof.challenge >= k256_order() {
                error!("the challenge is not in the field");
                return Err(InternalError::ProtocolError(None));
            }
            if pisch_proof.response >= k256_order() {
                error!("the response is not in the field");
                return Err(InternalError::ProtocolError(None));
            }
        }
        Ok(pisch_proofs)
    }

    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Keygen(KeygenMessageType::R3Proof))?;

        let pisch_proof: PiSchProof = deserialize!(&message.unverified_bytes)?;
        if pisch_proof.challenge >= k256_order() {
            error!("the challenge is not in the field");
            return Err(InternalError::ProtocolError(None));
        }
        if pisch_proof.response >= k256_order() {
            error!("the response is not in the field");
            return Err(InternalError::ProtocolError(None));
        }
        Ok(pisch_proof)
    }
    fn fill_transcript(
        transcript: &mut Transcript,
        context: &impl ProofContext,
        input: &CommonInput,
        commitment: &CurvePoint,
    ) -> Result<()> {
        transcript.append_message(b"PiSch ProofContext", &context.as_bytes()?);
        transcript.append_message(b"PiSch CommonInput", &serialize!(&input)?);
        transcript.append_message(b"PiSch Commitment", &serialize!(commitment)?);
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

    type TestFn = fn(PiSchProof, CommonInput) -> Result<()>;

    fn with_random_schnorr_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        additive: bool,
        test_code: impl Fn(PiSchProof, CommonInput) -> Result<()>,
    ) -> Result<()> {
        let q = k256_order();
        let g = CurvePoint::GENERATOR;

        let mut x = random_positive_bn(rng, &q);
        let x_commit = g.multiply_by_bignum(&x)?;
        if additive {
            x += random_positive_bn(rng, &q);
        }

        let input = CommonInput::new(&x_commit);

        // Proving knowledge of the random secret x
        let proof = PiSchProof::prove(input, ProverSecret::new(&x), &(), &mut transcript(), rng)?;

        test_code(proof, input)?;
        Ok(())
    }

    #[test]
    fn proof_commitment_field_must_match_input() -> Result<()> {
        let mut rng = init_testing();

        let q = k256_order();
        let g = CurvePoint::GENERATOR;

        let x = random_positive_bn(&mut rng, &q);

        let x_commit = g.multiply_by_bignum(&x)?;

        // Generating random commitment
        let y = random_positive_bn(&mut rng, &q);
        let y_commit = g.multiply_by_bignum(&y)?;

        let input = CommonInput::new(&x_commit);
        let com = PiSchProof::precommit(&mut rng)?;
        let mut proof = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &ProverSecret::new(&y),
            &transcript(),
        )?;
        proof.commitment = y_commit;
        assert!(proof.verify(input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn proof_response_field_must_match_input() -> Result<()> {
        let mut rng = init_testing();

        let q = k256_order();
        let g = CurvePoint::GENERATOR;

        let x = random_positive_bn(&mut rng, &q);

        let x_commit = g.multiply_by_bignum(&x)?;

        let input = CommonInput::new(&x_commit);
        let com = PiSchProof::precommit(&mut rng)?;
        let mut proof = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &ProverSecret::new(&x),
            &transcript(),
        )?;
        proof.response = random_positive_bn(&mut rng, &q);
        assert!(proof.verify(input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn generator_must_be_correct() -> Result<()> {
        let mut rng = init_testing();

        let q = k256_order();
        let g = CurvePoint::GENERATOR;

        let x = random_positive_bn(&mut rng, &q);

        let x_commit = g.multiply_by_bignum(&x)?;
        let bad_generator = x_commit.multiply_by_bignum(&x)?;

        let input = CommonInput::new(&bad_generator);
        let com = PiSchProof::precommit(&mut rng)?;
        let proof = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &ProverSecret::new(&x),
            &transcript(),
        )?;
        assert!(proof.verify(input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn secret_input_must_be_the_same_proving_and_verifying() -> Result<()> {
        let mut rng = init_testing();

        let q = k256_order();
        let g = CurvePoint::GENERATOR;

        let x = random_positive_bn(&mut rng, &q);

        let x_commit = g.multiply_by_bignum(&x)?;

        // Generating random `y` for bad secret input
        let y = random_positive_bn(&mut rng, &q);
        assert_ne!(x, y);

        let input = CommonInput::new(&x_commit);
        let com = PiSchProof::precommit(&mut rng)?;
        let proof = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &ProverSecret::new(&y),
            &transcript(),
        )?;
        assert!(proof.verify(input, &(), &mut transcript()).is_err());

        Ok(())
    }

    #[test]
    fn common_input_must_be_the_same_proving_and_verifying() -> Result<()> {
        let mut rng = init_testing();

        let q = k256_order();
        let g = CurvePoint::GENERATOR;

        let x = random_positive_bn(&mut rng, &q);

        let x_commit = g.multiply_by_bignum(&x)?;

        // Generating random commitment to `y` for generating random input for verifying
        // the proof than which was used to create it
        let y = random_positive_bn(&mut rng, &q);
        let y_commit = g.multiply_by_bignum(&y)?;
        assert_ne!(x_commit, y_commit);

        let input = CommonInput::new(&x_commit);
        let com = PiSchProof::precommit(&mut rng)?;
        let proof = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &ProverSecret::new(&y),
            &transcript(),
        )?;
        let bad_input = CommonInput::new(&y_commit);
        assert!(proof.verify(bad_input, &(), &mut transcript()).is_err());

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

        let q = k256_order();
        let g = CurvePoint::GENERATOR;

        let x = random_positive_bn(&mut rng, &q);
        let x_commit = g.multiply_by_bignum(&x)?;

        let input = CommonInput::new(&x_commit);
        let com = PiSchProof::precommit(&mut rng)?;
        let proof = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &ProverSecret::new(&x),
            &transcript(),
        )?;
        proof.verify(input, &(), &mut transcript())?;

        //test transcript mismatch
        let transcript2 = Transcript::new(b"some other external proof stuff");
        let proof3 = PiSchProof::prove_from_precommit(
            &(),
            &com,
            &input,
            &ProverSecret::new(&x),
            &transcript2,
        )?;
        assert!(proof3.verify(input, &(), &mut transcript()).is_err());

        Ok(())
    }
}
