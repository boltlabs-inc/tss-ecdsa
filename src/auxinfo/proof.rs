// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::participant::AuxInfoParticipant,
    errors::Result,
    messages::{AuxinfoMessageType, Message, MessageType},
    participant::InnerProtocolParticipant,
    ring_pedersen::VerifiedRingPedersen,
    Identifier,
};

use crate::zkp::{pifac, pimod, Proof, ProofContext};

use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Proofs used to validate correctness of the RSA modulus `N`.
///
/// This type includes proofs for `𝚷[fac]` and `𝚷[mod]`.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoProof {
    pimod: pimod::PiModProof,
    pifac: pifac::PiFacProof,
}

/// Common input and setup parameters known to both the prover and the verifier.
#[derive(Clone)]
pub(crate) struct CommonInput<'a> {
    shared_context: &'a <AuxInfoParticipant as InnerProtocolParticipant>::Context,
    sid: Identifier,
    rho: [u8; 32],
    setup_parameters: &'a VerifiedRingPedersen,
    modulus: &'a BigNumber,
}

impl<'a> CommonInput<'a> {
    /// Collect common parameters for proving or verifying a [`AuxInfoProof`]
    pub(crate) fn new(
        shared_context: &'a <AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
        verifier_setup_parameters: &'a VerifiedRingPedersen,
        modulus: &'a BigNumber,
    ) -> CommonInput<'a> {
        Self {
            shared_context,
            sid,
            rho,
            setup_parameters: verifier_setup_parameters,
            modulus,
        }
    }
}

impl AuxInfoProof {
    /// Generate a fresh transcript to be used in [`AuxInfoProof`].
    fn new_transcript() -> Transcript {
        Transcript::new(b"AuxInfoProof")
    }

    /// Convert a [`Message`] into an [`AuxInfoProof`].
    ///
    /// Note: This conversion **does not validate** the produced
    /// [`AuxInfoProof`]!
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Auxinfo(AuxinfoMessageType::R3Proof))?;
        let auxinfo_proof: AuxInfoProof = deserialize!(&message.unverified_bytes)?;
        Ok(auxinfo_proof)
    }

    /// Construct a proof that the modulus `N` is a valid product of two large
    /// primes `p` and `q` (`𝚷[mod]`) and that neither `p` nor `q` are small
    /// (`𝚷[fac]`).
    ///
    /// Note: The [`VerifiedRingPedersen`] argument **must be** provided by the
    /// verifier!
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        common_input: &CommonInput,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self> {
        let mut transcript = Self::new_transcript();
        Self::append_pimod_transcript(
            &mut transcript,
            common_input.shared_context,
            common_input.sid,
            common_input.rho,
        )?;
        let pimod = pimod::PiModProof::prove(
            pimod::CommonInput::new(common_input.modulus),
            pimod::ProverSecret::new(p, q),
            common_input.shared_context,
            &mut transcript,
            rng,
        )?;
        Self::append_pifac_transcript(
            &mut transcript,
            common_input.shared_context,
            common_input.sid,
            common_input.rho,
        )?;
        let pifac = pifac::PiFacProof::prove(
            pifac::CommonInput::new(common_input.setup_parameters, common_input.modulus),
            pifac::ProverSecret::new(p, q),
            common_input.shared_context,
            &mut transcript,
            rng,
        )?;

        Ok(Self { pimod, pifac })
    }

    /// Verify a proof that the modulus `N` is a valid product of two large
    /// primes `p` and `q` (`𝚷[mod]`) and that neither `p` nor `q` are small
    /// (`𝚷[fac]`).
    ///
    /// Note: The [`VerifiedRingPedersen`] argument **must be** provided by the
    /// verifier!
    pub(crate) fn verify(self, common_input: &CommonInput) -> Result<()> {
        let mut transcript = Self::new_transcript();
        Self::append_pimod_transcript(
            &mut transcript,
            common_input.shared_context,
            common_input.sid,
            common_input.rho,
        )?;
        self.pimod.verify(
            pimod::CommonInput::new(common_input.modulus),
            common_input.shared_context,
            &mut transcript,
        )?;
        Self::append_pifac_transcript(
            &mut transcript,
            common_input.shared_context,
            common_input.sid,
            common_input.rho,
        )?;
        self.pifac.verify(
            pifac::CommonInput::new(common_input.setup_parameters, common_input.modulus),
            common_input.shared_context,
            &mut transcript,
        )?;
        Ok(())
    }

    /// Append info relevant to the `𝚷[mod]` proof to the provided
    /// [`Transcript`].
    fn append_pimod_transcript(
        transcript: &mut Transcript,
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
    ) -> Result<()> {
        transcript.append_message(b"PaillierBumModulusProof", b"");
        transcript.append_message(b"PiMod ProofContext", &context.as_bytes()?);
        transcript.append_message(b"Session Id", &serialize!(&sid)?);
        transcript.append_message(b"rho", &rho);
        Ok(())
    }

    /// Append info relevant to the `𝚷[fac]` proof to the provided
    /// [`Transcript`].
    fn append_pifac_transcript(
        transcript: &mut Transcript,
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
    ) -> Result<()> {
        transcript.append_message(b"PiFacProof", b"");
        transcript.append_message(b"PiFac ProofContext", &context.as_bytes()?);
        transcript.append_message(b"Session Id", &serialize!(&sid)?);
        transcript.append_message(b"rho", &rho);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{paillier::prime_gen, protocol::SharedContext, utils::testing::init_testing};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn random_auxinfo_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        test_code: impl FnOnce(CommonInput, AuxInfoProof) -> Result<()>,
    ) -> Result<()> {
        let sid = Identifier::random(rng);
        let rho = rng.gen();
        let setup_params = VerifiedRingPedersen::gen(rng, &()).unwrap();
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(rng).unwrap();
        let modulus = &p * &q;
        let shared_context = SharedContext::random(rng);
        let common_input = CommonInput::new(&shared_context, sid, rho, &setup_params, &modulus);
        let proof = AuxInfoProof::prove(rng, &common_input, &p, &q).unwrap();
        test_code(common_input, proof)
    }

    #[test]
    fn auxinfo_proof_verifies() -> Result<()> {
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let rho = rng.gen();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let modulus = &p * &q;
        let shared_context = SharedContext::random(&mut rng);
        let common_input = CommonInput::new(&shared_context, sid, rho, &setup_params, &modulus);
        let proof = AuxInfoProof::prove(&mut rng, &common_input, &p, &q)?;
        assert!(proof.verify(&common_input).is_ok());
        Ok(())
    }

    #[test]
    fn each_constituent_proof_must_be_valid() -> Result<()> {
        let mut rng = init_testing();
        let mut rng2 = StdRng::from_rng(&mut rng).unwrap();
        let f = |input: CommonInput, proof: AuxInfoProof| {
            let f1 = |input1: CommonInput, proof1: AuxInfoProof| {
                let mix_one = AuxInfoProof {
                    pifac: proof.pifac,
                    pimod: proof1.pimod,
                };
                let mix_two = AuxInfoProof {
                    pifac: proof1.pifac,
                    pimod: proof.pimod,
                };
                assert!(mix_one.verify(&input).is_err());
                assert!(mix_two.verify(&input1).is_err());
                Ok(())
            };
            random_auxinfo_proof(&mut rng2, f1)?;
            Ok(())
        };
        random_auxinfo_proof(&mut rng, f)?;
        Ok(())
    }

    #[test]
    fn modulus_factors_must_be_correct() -> Result<()> {
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let rho = rng.gen();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let (p1, q1) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let modulus = &p * &q;
        let shared_context = &SharedContext::random(&mut rng);
        let common_input = CommonInput::new(shared_context, sid, rho, &setup_params, &modulus);
        match AuxInfoProof::prove(&mut rng, &common_input, &p1, &q1) {
            Ok(proof) => assert!(proof.verify(&common_input).is_err()),
            Err(_) => return Ok(()),
        }
        Ok(())
    }

    #[test]
    fn context_must_be_correct() -> Result<()> {
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let rho = rng.gen();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let modulus = &p * &q;
        let shared_context = &SharedContext::random(&mut rng);
        let bad_shared_context = &SharedContext::random(&mut rng);
        let common_input = CommonInput {
            shared_context,
            sid,
            rho,
            setup_parameters: &setup_params,
            modulus: &modulus,
        };
        let bad_common_input = CommonInput {
            shared_context: bad_shared_context,
            sid,
            rho,
            setup_parameters: &setup_params,
            modulus: &modulus,
        };
        match AuxInfoProof::prove(&mut rng, &common_input, &p, &q) {
            Ok(proof) => assert!(proof.verify(&bad_common_input).is_err()),
            Err(_) => return Ok(()),
        }
        Ok(())
    }
}
