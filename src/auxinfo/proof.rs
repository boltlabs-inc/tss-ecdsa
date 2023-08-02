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

use crate::zkp::Proof2;
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
            &pimod::CommonInput::new(N),
            &pimod::ProverSecret::new(p, q),
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
            .verify(&pimod::CommonInput::new(N), context, &mut transcript)?;
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
    use rand::random;
    use rocket::response::content;

    use crate::utils::testing::init_testing;
    use crate::paillier::prime_gen;

    use super::*;

    #[test]
    fn auxinfo_proof_verifies() -> Result<()> {
        let rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let rho = random(); 
        let setup_params = VerifiedRingPedersen::gen(&mut rng, &())?;
        let modulus = prime_gen::try_get_prime_from_pool_insecure(&mut rng).unwrap();
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let proof = AuxInfoProof::prove(&mut rng, &(), sid, rho, &setup_params, &modulus, &p, &q)?;
        assert!(proof.verify(&(), sid, rho, &setup_params, &modulus).is_ok());
        Ok(())
    }
}