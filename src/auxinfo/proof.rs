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

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoProof {
    pub pimod: PiModProof,
    pub pifac: PiFacProof,
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
        setup_params: &VerifiedRingPedersen,
        N: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self> {
        let mut pimod_transcript = Transcript::new(b"PaillierBlumModulusProof");
        pimod_transcript.append_message(b"PiMod ProofContext", &context.as_bytes()?);
        pimod_transcript.append_message(b"Session Id", &serialize!(&sid)?);
        pimod_transcript.append_message(b"rho", &rho);
        let pimod = PiModProof::prove(
            &PiModInput::new(N),
            &PiModSecret::new(p, q),
            context,
            &mut pimod_transcript,
            rng,
        )?;
        let mut pifac_transcript = Transcript::new(b"PiFacProof");
        pifac_transcript.append_message(b"PiFac ProofContext", &context.as_bytes()?);
        pifac_transcript.append_message(b"Session Id", &serialize!(&sid)?);
        pifac_transcript.append_message(b"rho", &rho);
        let pifac = PiFacProof::prove(
            &PiFacInput::new(setup_params, N),
            &PiFacSecret::new(p, q),
            context,
            &mut pifac_transcript,
            rng,
        )?;

        Ok(Self { pimod, pifac })
    }

    ///`sid` corresponds to a unique session identifier.
    pub(crate) fn verify(
        &self,
        context: &<AuxInfoParticipant as InnerProtocolParticipant>::Context,
        sid: Identifier,
        rho: [u8; 32],
        params: &VerifiedRingPedersen,
        N: &BigNumber,
    ) -> Result<()> {
        let mut pimod_transcript = Transcript::new(b"PaillierBlumModulusProof");
        pimod_transcript.append_message(b"PiMod ProofContext", &context.as_bytes()?);
        pimod_transcript.append_message(b"Session Id", &serialize!(&sid)?);
        pimod_transcript.append_message(b"rho", &rho);
        self.pimod
            .verify(&PiModInput::new(N), context, &mut pimod_transcript)?;
        let mut pifac_transcript = Transcript::new(b"PiFacProof");
        pifac_transcript.append_message(b"PiFac ProofContext", &context.as_bytes()?);
        pifac_transcript.append_message(b"Session Id", &serialize!(&sid)?);
        pifac_transcript.append_message(b"rho", &rho);
        self.pifac
            .verify(&PiFacInput::new(params, N), context, &mut pifac_transcript)?;
        Ok(())
    }
}
