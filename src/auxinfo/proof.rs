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
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
        verifier_params: &VerifiedRingPedersen,
        N: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self> {
        let mut transcript = Self::new_transcript();
        Self::append_pimod_transcript(&mut transcript, context, sid, rho)?;
        let pimod = pimod::PiModProof::prove(
            pimod::CommonInput::new(N),
            pimod::ProverSecret::new(p, q),
            context,
            &mut transcript,
            rng,
        )?;
        Self::append_pifac_transcript(&mut transcript, context, sid, rho)?;
        let pifac = pifac::PiFacProof::prove(
            pifac::CommonInput::new(verifier_params, N),
            pifac::ProverSecret::new(p, q),
            context,
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
    pub(crate) fn verify(
        self,
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
        verifier_params: &VerifiedRingPedersen,
        N: &BigNumber,
    ) -> Result<()> {
        let mut transcript = Self::new_transcript();
        Self::append_pimod_transcript(&mut transcript, context, sid, rho)?;
        self.pimod
            .verify(pimod::CommonInput::new(N), context, &mut transcript)?;
        Self::append_pifac_transcript(&mut transcript, context, sid, rho)?;
        self.pifac.verify(
            pifac::CommonInput::new(verifier_params, N),
            context,
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
    use rand::{random, Rng};

    #[test]
    fn auxinfo_proof_verifies() -> Result<()> {
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let rho = random();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let modulus = &p * &q;
        let shared_context = SharedContext::random(&mut rng);
        let proof = AuxInfoProof::prove(
            &mut rng,
            &shared_context,
            sid,
            rho,
            &setup_params,
            &modulus,
            &p,
            &q,
        )?;
        assert!(proof
            .verify(&shared_context, sid, rho, &setup_params, &modulus)
            .is_ok());
        Ok(())
    }

    #[test]
    fn each_constituent_proof_must_be_valid() -> Result<()> {
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let rho = rng.gen();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let modulus = &p * &q;
        let shared_context = &SharedContext::random(&mut rng);
        let mut transcript = AuxInfoProof::new_transcript();
        AuxInfoProof::append_pimod_transcript(&mut transcript, shared_context, sid, rho)?;
        let pimod = pimod::PiModProof::prove(
            &pimod::CommonInput::new(&modulus),
            &pimod::ProverSecret::new(&p, &q),
            shared_context,
            &mut transcript,
            &mut rng,
        )?;
        AuxInfoProof::append_pifac_transcript(&mut transcript, shared_context, sid, rho)?;
        let pifac = pifac::PiFacProof::prove(
            pifac::CommonInput::new(&setup_params, &modulus),
            pifac::ProverSecret::new(&p, &q),
            shared_context,
            &mut transcript,
            &mut rng,
        )?;
        let proof = AuxInfoProof {
            pimod: pimod.clone(),
            pifac: pifac.clone(),
        };
        assert!(proof
            .verify(shared_context, sid, rho, &setup_params, &modulus)
            .is_ok());
        let sid1 = Identifier::random(&mut rng);
        let rho1: [u8; 32] = rng.gen();
        let setup_params1 = VerifiedRingPedersen::gen(&mut rng, &())?;
        let (p1, q1) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let modulus1 = &p1 * &q1;
        let shared_context1 = &SharedContext::random(&mut rng);
        let mut transcript1 = AuxInfoProof::new_transcript();
        AuxInfoProof::append_pimod_transcript(&mut transcript1, shared_context1, sid1, rho1)?;
        let pimod1 = pimod::PiModProof::prove(
            &pimod::CommonInput::new(&modulus1),
            &pimod::ProverSecret::new(&p1, &q1),
            shared_context1,
            &mut transcript1,
            &mut rng,
        )?;
        AuxInfoProof::append_pifac_transcript(&mut transcript1, shared_context1, sid1, rho1)?;
        let pifac1 = pifac::PiFacProof::prove(
            pifac::CommonInput::new(&setup_params1, &modulus1),
            pifac::ProverSecret::new(&p1, &q1),
            shared_context1,
            &mut transcript1,
            &mut rng,
        )?;
        let proof1 = AuxInfoProof {
            pimod: pimod1.clone(),
            pifac: pifac1.clone(),
        };
        assert!(proof1
            .verify(shared_context1, sid1, rho1, &setup_params1, &modulus1)
            .is_ok());
        let proof2 = AuxInfoProof {
            pimod,
            pifac: pifac1,
        };
        assert!(proof2
            .verify(shared_context1, sid1, rho1, &setup_params1, &modulus1)
            .is_err());
        let proof3 = AuxInfoProof {
            pimod: pimod1,
            pifac,
        };
        assert!(proof3
            .verify(shared_context1, sid1, rho1, &setup_params1, &modulus1)
            .is_err());
        Ok(())
    }

    #[test]
    fn pimod_pifac_proofs_must_be_correct_individually() -> Result<()> {
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let rho = random();
        let bad_rho: [u8; 32] = random();
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let modulus = &p * &q;
        let shared_context = &SharedContext::random(&mut rng);
        let mut transcript = AuxInfoProof::new_transcript();
        AuxInfoProof::append_pimod_transcript(&mut transcript, shared_context, sid, bad_rho)?;
        let bad_pimod = pimod::PiModProof::prove(
            &pimod::CommonInput::new(&modulus),
            &pimod::ProverSecret::new(&p, &q),
            shared_context,
            &mut transcript,
            &mut rng,
        )?;
        AuxInfoProof::append_pifac_transcript(&mut transcript, shared_context, sid, rho)?;
        let pifac = pifac::PiFacProof::prove(
            pifac::CommonInput::new(&setup_params, &modulus),
            pifac::ProverSecret::new(&p, &q),
            shared_context,
            &mut transcript,
            &mut rng,
        )?;
        let proof = AuxInfoProof {
            pimod: bad_pimod.clone(),
            pifac: pifac.clone(),
        };
        assert!(proof
            .verify(shared_context, sid, rho, &setup_params, &modulus)
            .is_err());
        AuxInfoProof::append_pimod_transcript(&mut transcript, shared_context, sid, rho)?;
        let pimod = pimod::PiModProof::prove(
            &pimod::CommonInput::new(&modulus),
            &pimod::ProverSecret::new(&p, &q),
            shared_context,
            &mut transcript,
            &mut rng,
        )?;
        AuxInfoProof::append_pifac_transcript(&mut transcript, shared_context, sid, bad_rho)?;
        let bad_pifac = pifac::PiFacProof::prove(
            pifac::CommonInput::new(&setup_params, &modulus),
            pifac::ProverSecret::new(&p, &q),
            shared_context,
            &mut transcript,
            &mut rng,
        )?;
        let proof = AuxInfoProof {
            pimod: pimod.clone(),
            pifac: bad_pifac.clone(),
        };
        assert!(proof
            .verify(shared_context, sid, rho, &setup_params, &modulus)
            .is_err());
        Ok(())
    }
}
