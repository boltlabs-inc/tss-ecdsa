// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::participant::AuxInfoParticipant,
    errors::{InternalError, Result},
    messages::{AuxinfoMessageType, MessageType},
    participant::InnerProtocolParticipant,
    ring_pedersen::VerifiedRingPedersen,
    zkp::{
        pifac::{PiFacInput, PiFacProof, PiFacSecret},
        pimod::{PiModInput, PiModProof, PiModSecret},
        Proof, ProofContext,
    },
    Identifier, Message,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::error;

/// Proofs used to validate correctness of the RSA modulus `N`.
///
/// This type includes proofs for `𝚷[fac]` and `𝚷[mod]`.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoProof {
    pimod: PiModProof,
    pifac: PiFacProof,
}

impl AuxInfoProof {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Auxinfo(AuxinfoMessageType::R3Proof) {
            error!(
                "Encountered unexpected MessageType. Expected {:?}, Got {:?}",
                MessageType::Auxinfo(AuxinfoMessageType::R3Proof),
                message.message_type()
            );
            return Err(InternalError::InternalInvariantFailed);
        }
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
        let mut pimod_transcript = Self::pimod_transcript(context, sid, rho)?;
        let pimod = PiModProof::prove(
            &PiModInput::new(N),
            &PiModSecret::new(p, q),
            context,
            &mut pimod_transcript,
            rng,
        )?;
        let mut pifac_transcript = Self::pifac_transcript(context, sid, rho)?;
        let pifac = PiFacProof::prove(
            &PiFacInput::new(verifier_params, N),
            &PiFacSecret::new(p, q),
            context,
            &mut pifac_transcript,
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
        &self,
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
        verifier_params: &VerifiedRingPedersen,
        N: &BigNumber,
    ) -> Result<()> {
        let mut pimod_transcript = Self::pimod_transcript(context, sid, rho)?;
        self.pimod
            .verify(&PiModInput::new(N), context, &mut pimod_transcript)?;
        let mut pifac_transcript = Self::pifac_transcript(context, sid, rho)?;
        self.pifac.verify(
            &PiFacInput::new(verifier_params, N),
            context,
            &mut pifac_transcript,
        )?;
        Ok(())
    }

    fn pimod_transcript(
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(b"PaillierBlumModulusProof");
        transcript.append_message(b"PiMod ProofContext", &context.as_bytes()?);
        transcript.append_message(b"Session Id", &serialize!(&sid)?);
        transcript.append_message(b"rho", &rho);
        Ok(transcript)
    }

    fn pifac_transcript(
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(b"PiFacProof");
        transcript.append_message(b"PiFac ProofContext", &context.as_bytes()?);
        transcript.append_message(b"Session Id", &serialize!(&sid)?);
        transcript.append_message(b"rho", &rho);
        Ok(transcript)
    }
}
