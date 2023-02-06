// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{InternalError, Result},
    messages::{AuxinfoMessageType, MessageType},
    ring_pedersen::VerifiedRingPedersen,
    zkp::{
        pifac::{PiFacInput, PiFacProof, PiFacSecret},
        pimod::{PiModInput, PiModProof, PiModSecret},
    },
    Identifier, Message,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoProof {
    pub pimod: PiModProof,
    pub pifac: PiFacProof,
}

impl AuxInfoProof {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Auxinfo(AuxinfoMessageType::R3Proof) {
            return Err(InternalError::IncorrectBroadcastMessageTag);
        }
        let auxinfo_proof: AuxInfoProof = deserialize!(&message.unverified_bytes)?;
        Ok(auxinfo_proof)
    }

    pub(crate) fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        sid: Identifier,
        rho: [u8; 32],
        setup_params: &VerifiedRingPedersen,
        N: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self> {
        let mut pimod_transcript = Transcript::new(b"PaillierBlumModulusProof");
        pimod_transcript.append_message(b"Session Id", &serialize!(&sid)?);
        pimod_transcript.append_message(b"rho", &rho);
        let pimod = PiModProof::prove_with_transcript(
            rng,
            &PiModInput::new(N),
            &PiModSecret::new(p, q),
            &mut pimod_transcript,
        )?;

        let mut pifac_transcript = Transcript::new(b"PiFacProof");
        pifac_transcript.append_message(b"Session Id", &serialize!(&sid)?);
        pifac_transcript.append_message(b"rho", &rho);
        let pifac = PiFacProof::prove_with_transcript(
            rng,
            &PiFacInput::new(setup_params, N),
            &PiFacSecret::new(p, q),
            &mut pifac_transcript,
        )?;

        Ok(Self { pimod, pifac })
    }

    pub(crate) fn verify(
        &self,
        sid: Identifier,
        rho: [u8; 32],
        params: &VerifiedRingPedersen,
        N: &BigNumber,
    ) -> Result<()> {
        let mut pimod_transcript = Transcript::new(b"PaillierBlumModulusProof");
        pimod_transcript.append_message(b"Session Id", &serialize!(&sid)?);
        pimod_transcript.append_message(b"rho", &rho);
        self.pimod
            .verify_with_transcript(&PiModInput::new(N), &mut pimod_transcript)?;

        let mut pifac_transcript = Transcript::new(b"PiFacProof");
        pifac_transcript.append_message(b"Session Id", &serialize!(&sid)?);
        pifac_transcript.append_message(b"rho", &rho);
        self.pifac
            .verify_with_transcript(&PiFacInput::new(params, N), &mut pifac_transcript)?;
        Ok(())
    }
}
