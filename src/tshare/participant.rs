//! Types and functions related to the key refresh sub-protocol Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use super::{
    commit::{TshareCommit, TshareDecommit},
    share::{CoeffPrivate, CoeffPublic, EvalEncrypted},
};
use crate::{
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{CallerError, InternalError, Result},
    local_storage::LocalStorage,
    messages::{Message, MessageType, TshareMessageType},
    participant::{
        Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant, Status,
    },
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    run_only_once,
    utils::{k256_order, CurvePoint},
    zkp::pisch::{CommonInput, PiSchPrecommit, PiSchProof, ProverSecret},
    Identifier, ParticipantConfig,
};

use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use tracing::{error, info, instrument, warn};

use super::{input::Input, output::Output};

mod storage {
    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = TshareCommit;
    }
    pub(super) struct Decommit;
    impl TypeTag for Decommit {
        type Value = TshareDecommit;
    }
    pub(super) struct VecSchnorrPrecom;
    impl TypeTag for VecSchnorrPrecom {
        type Value = Vec<PiSchPrecommit>;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct PrivateCoeffs;
    impl TypeTag for PrivateCoeffs {
        type Value = Vec<super::CoeffPrivate>;
    }
    pub(super) struct ValidPublicCoeffs;
    impl TypeTag for ValidPublicCoeffs {
        type Value = Vec<super::CoeffPublic>;
    }
    pub(super) struct ValidPrivateEval;
    impl TypeTag for ValidPrivateEval {
        type Value = super::CoeffPrivate;
    }
}

/**
This is a protocol that converts additive shares to Shamir shares.

Input:
- The threshold `t` of parties needed to reconstruct the shared secret.
- The auxiliary information for encryption.
- Optionally, an existing n-out-of-n share to be converted to t-out-of-n.

Rounds 1:
- Each participant generates a random polynomial of degree `threshold - 1`.
    - Alternatively, set an existing additive share as the constant term.
- Each participant commits to their polynomial and a Schnorr proof.

Rounds 2:
- Each participant decommits the public form of their polynomial and Schnorr proofs.

Rounds 3:
- Each participant shares a private evaluation of the polynomial with each of the other participants.

Output:
- The public commitment to the shared polynomial. It is represented in coefficients form in the exponent (EC points). The constant term corresponds to the shared value. This can be used to evaluate the commitment to the share of any participant.
- The private evaluation of the shared polynomial for our participant. `t` of those can reconstruct the secret.

*/
#[derive(Debug)]
pub struct TshareParticipant {
    /// The current session identifier
    sid: Identifier,
    /// The current protocol input.
    input: Input,
    /// A unique identifier for this participant.
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    /// Broadcast subprotocol handler
    broadcast_participant: BroadcastParticipant,
    /// Status of the protocol execution.
    status: Status,
}

impl ProtocolParticipant for TshareParticipant {
    type Input = Input;
    type Output = Output;

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self> {
        input.check_participant_config(&ParticipantConfig::new(id, &other_participant_ids)?)?;

        Ok(Self {
            sid,
            input,
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: Default::default(),
            broadcast_participant: BroadcastParticipant::new(sid, id, other_participant_ids, ())?,
            status: Status::NotReady,
        })
    }

    fn ready_type() -> MessageType {
        MessageType::Tshare(TshareMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Tshare
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        &self.other_participant_ids
    }

    fn sid(&self) -> Identifier {
        self.sid
    }

    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "TSHARE: Player {}: received {:?} from {}",
            self.id(),
            message.message_type(),
            message.from()
        );

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
        }

        if !self.status().is_ready() && message.message_type() != Self::ready_type() {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        match message.message_type() {
            MessageType::Tshare(TshareMessageType::Ready) => self.handle_ready_msg(rng, message),
            MessageType::Tshare(TshareMessageType::R1CommitHash) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_msg, rng)
            }
            MessageType::Tshare(TshareMessageType::R2Decommit) => {
                self.handle_round_two_msg(rng, message)
            }
            MessageType::Tshare(TshareMessageType::R3Proofs) => {
                self.handle_round_three_msg(message)
            }
            MessageType::Tshare(TshareMessageType::R3PrivateShare) => {
                self.handle_round_three_msg_private(message)
            }
            message_type => {
                error!(
                    "Incorrect MessageType given to TshareParticipant. Got: {:?}",
                    message_type
                );
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    fn status(&self) -> &Status {
        &self.status
    }
}

impl InnerProtocolParticipant for TshareParticipant {
    type Context = SharedContext;

    fn retrieve_context(&self) -> <Self as InnerProtocolParticipant>::Context {
        SharedContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.local_storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.local_storage
    }

    fn status_mut(&mut self) -> &mut Status {
        &mut self.status
    }
}

impl Broadcast for TshareParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl TshareParticipant {
    fn coeff_ids(&self) -> Vec<ParticipantIdentifier> {
        // TODO: Introduce dedicated types.
        (0..self.input.threshold())
            .map(|i| ParticipantIdentifier::from_u128(i as u128))
            .collect()
    }

    /// Handle "Ready" messages from the protocol participants.
    ///
    /// Once "Ready" messages have been received from all participants, this
    /// method will trigger this participant to generate its round one message.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling ready tshare message.");

        let ready_outcome = self.process_ready_message(rng, message)?;
        let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, message.id()))?;
        // extend the output with r1 messages (if they hadn't already been generated)
        Ok(ready_outcome.with_messages(round_one_messages))
    }

    /// Generate the protocol's round one message.
    ///
    /// The outcome is a broadcast message containing a commitment to:
    /// - shares [`CoeffPublic`] X_ij for all other participants,
    /// - a "pre-commitment" A to a Schnorr proof.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one tshare messages.");

        // Generate shares for all participants.
        let (coeff_privates, coeff_publics) = {
            let mut privates = vec![];
            let mut publics = vec![];

            for pid in self.coeff_ids() {
                let (private, public) = CoeffPublic::new_pair(pid, rng)?;
                privates.push(private);
                publics.push(public);
            }

            if let Some(private) = self.input.share() {
                privates[0] = private.clone();
                publics[0] = private.to_public(self.coeff_ids()[0])?;
            }

            (privates, publics)
        };

        // Generate proof precommitments.
        let sch_precoms = (0..coeff_publics.len())
            .map(|_| PiSchProof::precommit(rng))
            .collect::<Result<Vec<_>>>()?;

        let decom = TshareDecommit::new(
            rng,
            &sid,
            &self.id(),
            coeff_publics,
            sch_precoms
                .iter()
                .map(|sch_precom| *sch_precom.precommitment())
                .collect(),
        );

        // Store the beginning of our proofs so we can continue the proofs later.
        self.local_storage
            .store::<storage::VecSchnorrPrecom>(self.id(), sch_precoms);

        // Mark our own public shares as verified.
        self.local_storage
            .store::<storage::ValidPublicCoeffs>(self.id(), decom.coeff_publics.clone());

        // Store the private share from ourselves to ourselves.
        let my_private_share = Self::eval_private_share(&coeff_privates, self.id());
        self.local_storage
            .store::<storage::ValidPrivateEval>(self.id(), my_private_share);

        // Store the private coeffs from us to others so we can share them later.
        self.local_storage
            .store::<storage::PrivateCoeffs>(self.id(), coeff_privates);

        let com = decom.commit()?;
        let com_bytes = serialize!(&com)?;
        self.local_storage.store::<storage::Commit>(self.id(), com);

        // Store our committed values so we can open the commitment later.
        self.local_storage
            .store::<storage::Decommit>(self.id(), decom);

        let messages = self.broadcast(
            rng,
            MessageType::Tshare(TshareMessageType::R1CommitHash),
            com_bytes,
            sid,
            BroadcastTag::TshareR1CommitHash,
        )?;
        Ok(messages)
    }

    /// Handle round one messages from the protocol participants.
    ///
    /// In round one, each participant broadcasts its commitment to its public
    /// key share and a "precommitment" to a Schnorr proof. Once all such
    /// commitments have been received, this participant will send an opening of
    /// its own commitment to all other parties.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: BroadcastOutput,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        let message = broadcast_message.into_message(BroadcastTag::TshareR1CommitHash)?;

        self.check_for_duplicate_msg::<storage::Commit>(message.from())?;
        info!("Handling round one tshare message.");

        let tshare_commit = TshareCommit::from_message(&message)?;
        self.local_storage
            .store_once::<storage::Commit>(message.from(), tshare_commit)?;

        // Check if we've received all the commits, which signals an end to
        // round one.
        //
        // Note: This does _not_ check `self.all_participants` on purpose. There
        // could be a setting where we've received all the round one messages
        // from all other participants, yet haven't ourselves generated our
        // round one message. If we switched to `self.all_participants` here
        // then the result would be `false`, causing the execution to hang.
        //
        // The "right" solution would be to only process the message once the
        // "Ready" round is complete, and stashing messages if it is not yet
        // complete (a la how we do it in `handle_round_two_msg`).
        // Unfortunately, this does not work given the current API because we
        // are dealing with a [`BroadcastOutput`] type instead of a [`Message`]
        // type.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(self.other_ids());

        if r1_done {
            // Finish round 1 by generating messages for round 2
            let round_one_messages = run_only_once!(self.gen_round_two_msgs(rng, message.id()))?;

            // Process any round 2 messages we may have received early
            let round_two_outcomes = self
                .fetch_messages(MessageType::Tshare(TshareMessageType::R2Decommit))?
                .iter()
                .map(|msg| self.handle_round_two_msg(rng, msg))
                .collect::<Result<Vec<_>>>()?;

            ProcessOutcome::collect_with_messages(round_two_outcomes, round_one_messages)
        } else {
            // Otherwise, wait for more round 1 messages
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate the protocol's round two messages.
    ///
    /// The outcome is an opening to the commitment generated in round one.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two tshare messages.");

        let mut messages = vec![];
        // Check that we've generated our share before trying to retrieve it.
        //
        // Because we are not checking `self.all_participants` in
        // `handle_round_one_msg`, we may reach this point and not actually have
        // generated round one messages for ourselves (in particular,
        // `CoeffPublic` and `Decommit`). This check forces that behavior.
        // Without it we'll get a `InternalInvariantFailed` error when trying to
        // retrieve `Decommit` below.
        if !self.local_storage.contains::<storage::Decommit>(self.id()) {
            let more_messages = run_only_once!(self.gen_round_one_msgs(rng, sid))?;
            messages.extend_from_slice(&more_messages);
        }

        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(self.id())?;
        let more_messages = self.message_for_other_participants(
            MessageType::Tshare(TshareMessageType::R2Decommit),
            decom,
        )?;
        messages.extend_from_slice(&more_messages);
        Ok(messages)
    }

    /// Handle the protocol's round two messages.
    ///
    /// Here we check that the decommitments from each participant are valid.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::Decommit>(message.from())?;
        info!("Handling round two tshare message.");

        // We must receive all commitments in round 1 before we start processing
        // decommits in round 2.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(&self.all_participants());
        if !r1_done {
            // Store any early round 2 messages
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        // Check that the decommitment contained in the message is valid against
        // the previously received commitment and protocol rules.
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(message.from())?;
        let decom = TshareDecommit::from_message(message, com, self.input.threshold())?;
        self.local_storage
            .store_once::<storage::Decommit>(message.from(), decom)?;

        // Check if we've received all the decommits
        let r2_done = self
            .local_storage
            .contains_for_all_ids::<storage::Decommit>(&self.all_participants());

        if r2_done {
            // Generate messages for round 3...
            let round_three_messages = run_only_once!(self.gen_round_three_msgs(rng))?;

            // ...and handle any messages that other participants have sent for round 3.
            let mut round_three_outcomes = self
                .fetch_messages(MessageType::Tshare(TshareMessageType::R3Proofs))?
                .iter()
                .map(|msg| self.handle_round_three_msg(msg))
                .collect::<Result<Vec<_>>>()?;

            let outcomes_private = self
                .fetch_messages(MessageType::Tshare(TshareMessageType::R3PrivateShare))?
                .iter()
                .map(|msg| self.handle_round_three_msg_private(msg))
                .collect::<Result<Vec<_>>>()?;
            round_three_outcomes.extend(outcomes_private);

            ProcessOutcome::collect_with_messages(round_three_outcomes, round_three_messages)
        } else {
            // Otherwise, wait for more round 2 messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate the protocol's round three messages.
    ///
    /// At this point, we have validated each participant's commitment, and can
    /// now proceed to constructing a Schnorr proof that this participant knows
    /// the private value corresponding to its public key share.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>> {
        info!("Generating round three tshare messages.");

        // Construct `global rid` out of each participant's `rid`s.
        let my_rid = self
            .local_storage
            .retrieve::<storage::Decommit>(self.id())?
            .rid;
        let rids: Vec<[u8; 32]> = self
            .other_ids()
            .iter()
            .map(|&other_participant_id| {
                let decom = self
                    .local_storage
                    .retrieve::<storage::Decommit>(other_participant_id)?;
                Ok(decom.rid)
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let mut global_rid = my_rid;
        // xor all the rids together.
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.local_storage
            .store::<storage::GlobalRid>(self.id(), global_rid);

        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(self.id())?;

        let transcript = schnorr_proof_transcript(self.sid(), &global_rid, self.id())?;

        // Generate proofs for each share.
        let precoms = self
            .local_storage
            .retrieve::<storage::VecSchnorrPrecom>(self.id())?;

        let private_coeffs = self
            .local_storage
            .retrieve::<storage::PrivateCoeffs>(self.id())?;

        let mut proofs: Vec<PiSchProof> = vec![];
        for i in 0..precoms.len() {
            let pk = &decom.coeff_publics[i];
            let input = CommonInput::new(pk);
            let precom = &precoms[i];
            let sk = &private_coeffs[i];

            let proof = PiSchProof::prove_from_precommit(
                &self.retrieve_context(),
                precom,
                &input,
                &ProverSecret::new(sk.as_ref()),
                &transcript,
            )?;

            proofs.push(proof);
        }

        // Encrypt the private shares to each participant.
        let encrypted_shares = self
            .other_ids()
            .iter()
            .map(|other_participant_id| {
                let private_share =
                    Self::eval_private_share(&private_coeffs, *other_participant_id);

                let auxinfo = self.input.find_auxinfo_public(*other_participant_id)?;
                EvalEncrypted::encrypt(&private_share, auxinfo.pk(), rng)
            })
            .collect::<Result<Vec<_>>>()?;

        // Send all proofs to everybody.
        let mut messages = self.message_for_other_participants(
            MessageType::Tshare(TshareMessageType::R3Proofs),
            proofs,
        )?;

        // Send their private shares to each individual participant.
        messages.extend(
            self.other_ids()
                .iter()
                .zip(encrypted_shares.iter())
                .map(|(other_participant_id, encrypted_share)| {
                    Message::new(
                        MessageType::Tshare(TshareMessageType::R3PrivateShare),
                        self.sid(),
                        self.id(),
                        *other_participant_id,
                        encrypted_share,
                    )
                })
                .collect::<Result<Vec<Message>>>()?,
        );

        Ok(messages)
    }

    /// Assign a non-null x coordinate to each participant.
    fn participant_coordinate(pid: ParticipantIdentifier) -> BigNumber {
        BigNumber::from(pid.as_u128()) + BigNumber::one()
    }

    fn eval_private_share(
        coeff_privates: &[CoeffPrivate],
        recipient_id: ParticipantIdentifier,
    ) -> CoeffPrivate {
        // TODO: Enforce that no participant ID equals the shared evaluation point
        // (0, constant term).
        // TODO: Use a field type.

        let x = Self::participant_coordinate(recipient_id);
        let mut sum = BigNumber::zero();
        for coeff in coeff_privates.iter().rev() {
            sum *= &x;
            sum = sum.modadd(&coeff.x, &k256_order());
        }
        // TODO: introduce a different type for evaluations.
        CoeffPrivate { x: sum }
    }

    fn eval_public_share(
        coeff_publics: &[CoeffPublic],
        recipient_id: ParticipantIdentifier,
    ) -> Result<CurvePoint> {
        let x = Self::participant_coordinate(recipient_id);
        let mut sum = CurvePoint::IDENTITY;
        for coeff in coeff_publics.iter().rev() {
            sum = sum.multiply_by_bignum(&x)?;
            sum = sum + *coeff.as_ref();
        }
        Ok(sum)
    }

    /// Handle round three messages only after our own `gen_round_three_msgs`.
    fn can_handle_round_three_msg(&self) -> bool {
        self.local_storage.contains::<storage::GlobalRid>(self.id())
    }

    /// Handle the protocol's round three public messages.
    ///
    /// Here we validate the Schnorr proofs from each participant.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::ValidPublicCoeffs>(message.from())?;

        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three tshare broadcast message.");
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        info!("Handling round three tshare broadcast message.");

        let global_rid = *self
            .local_storage
            .retrieve::<storage::GlobalRid>(self.id())?;

        let proofs = PiSchProof::from_message_multi(message)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;

        // Check that there is one proof per coeff.
        // TODO: check (or compute) the exact value of the eval points.
        if proofs.len() != decom.coeff_publics.len() {
            error!("Received incorrect number of proofs",);
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        for ((proof, precommit), public_share) in proofs
            .into_iter()
            .zip(decom.As.iter())
            .zip(decom.coeff_publics.iter())
        {
            let mut transcript = schnorr_proof_transcript(self.sid(), &global_rid, message.from())?;
            proof.verify_with_precommit(
                CommonInput::new(public_share),
                &self.retrieve_context(),
                &mut transcript,
                precommit,
            )?;
        }

        // Only if the proof verifies do we store the participant's shares.
        self.local_storage
            .store_once::<storage::ValidPublicCoeffs>(
                message.from(),
                decom.coeff_publics.clone(),
            )?;

        self.maybe_finish()
    }

    /// Handle the protocol's round three private messages.
    ///
    /// Here we validate and store a private share from someone to us.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg_private(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::ValidPrivateEval>(message.from())?;

        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three tshare private message.");
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        info!("Handling round three tshare private message.");

        message.check_type(MessageType::Tshare(TshareMessageType::R3PrivateShare))?;
        let encrypted_share: EvalEncrypted = deserialize!(&message.unverified_bytes)?;

        // Get my private key from the AuxInfo protocol.
        let my_dk = self.input.private_auxinfo().decryption_key();

        // Decrypt the private share.
        let private_share = encrypted_share.decrypt(my_dk)?;

        // Check that this private share matches our public share in TshareDecommit
        // from this participant.
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;
        let expected_public = Self::eval_public_share(&decom.coeff_publics, self.id())?;
        let implied_public = private_share.public_point()?;
        if implied_public != expected_public {
            error!("the private share does not match the public share");
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        self.local_storage
            .store::<storage::ValidPrivateEval>(message.from(), private_share);

        self.maybe_finish()
    }

    fn maybe_finish(&mut self) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        // Have we validated and stored the public shares from everybody to everybody?
        let got_all_public_shares = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPublicCoeffs>(&self.all_participants());

        // Have we got the private shares from everybody to us?
        let got_all_private_shares = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPrivateEval>(&self.all_participants());

        // If so, we completed the protocol! Return the outputs.
        if got_all_public_shares && got_all_private_shares {
            // Compute the public polynomial.
            let coeffs_from_all = self
                .all_participants()
                .iter()
                .map(|pid| {
                    self.local_storage
                        .remove::<storage::ValidPublicCoeffs>(*pid)
                })
                .collect::<Result<Vec<_>>>()?;
            let all_public_coeffs = Self::aggregate_public_coeffs(&&coeffs_from_all);

            // Compute the one's own private evaluation.
            let from_all_to_me_private = self
                .all_participants()
                .iter()
                .map(|pid| self.local_storage.remove::<storage::ValidPrivateEval>(*pid))
                .collect::<Result<Vec<_>>>()?;
            let my_private_share = Self::aggregate_private_shares(&from_all_to_me_private);

            // Double-check that the aggregated private share matches the aggregated public
            // coeffs.
            let expected_public = Self::eval_public_share(&all_public_coeffs, self.id())?;
            let implied_public = my_private_share.public_point()?;
            if implied_public != expected_public {
                error!("the aggregated private share does not match the public coeffs");
                return Err(InternalError::InternalInvariantFailed);
            }

            // Return the output and stop.
            let all_public_coeffs = all_public_coeffs
                .iter()
                .enumerate()
                .map(|(i, coeff)| coeff.to_keyshare(i))
                .collect();
            let output = Output::from_parts(all_public_coeffs, my_private_share.to_keyshare())?;

            // Check that the new shared value is consistent with the old one (if given).
            /*if let Some(share) = self.input.share() {
                let old_public = // TODO: get previous public shared value.
                if old_public != all_public_coeffs[0] {
                    error!("The new public key share is inconsistent with the old one.");
                    return Err(InternalError::ProtocolError(None));
                }
            }*/

            self.status = Status::TerminatedSuccessfully;
            Ok(ProcessOutcome::Terminated(output))
        } else {
            // Otherwise, we'll have to wait for more round three messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    fn aggregate_private_shares(private_shares: &[CoeffPrivate]) -> CoeffPrivate {
        CoeffPrivate::sum(private_shares)
    }

    /// Return coeffs.sum(axis=0)
    fn aggregate_public_coeffs(coeffs_from_all: &[Vec<CoeffPublic>]) -> Vec<CoeffPublic> {
        let n_coeffs = coeffs_from_all[0].len();
        (0..n_coeffs)
            .map(|i| {
                let sum = coeffs_from_all
                    .iter()
                    .fold(CurvePoint::IDENTITY, |sum, coeffs| {
                        sum + *coeffs[i].as_ref()
                    });
                CoeffPublic::new(sum)
            })
            .collect()
    }
}

/// Generate a [`Transcript`] for [`PiSchProof`].
fn schnorr_proof_transcript(
    sid: Identifier,
    global_rid: &[u8; 32],
    sender_id: ParticipantIdentifier,
) -> Result<Transcript> {
    let mut transcript = Transcript::new(b"tshare schnorr");
    transcript.append_message(b"sid", &serialize!(&sid)?);
    transcript.append_message(b"rid", &serialize!(global_rid)?);
    transcript.append_message(b"sender_id", &serialize!(&sender_id)?);
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use super::{super::input::Input, *};
    use crate::{
        auxinfo, keygen,
        utils::testing::{init_testing, init_testing_with_seed},
        Identifier, ParticipantConfig,
    };
    use rand::{CryptoRng, Rng, RngCore};
    use std::{
        collections::{HashMap, HashSet},
        iter::zip,
    };
    use tracing::debug;

    impl TshareParticipant {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            quorum_size: usize,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            // Prepare prereqs for making TshareParticipant's. Assume all the
            // simulations are stable (e.g. keep config order)
            let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
            let auxinfo_outputs = auxinfo::Output::simulate_set(&configs, rng);

            // Make the participants
            zip(configs, auxinfo_outputs)
                .map(|(config, auxinfo_output)| {
                    let input = Input::new(auxinfo_output, 2)?;
                    Self::new(sid, config.id(), config.other_ids().to_vec(), input)
                })
                .collect::<Result<Vec<_>>>()
        }

        pub fn initialize_tshare_message(&self, tshare_identifier: Identifier) -> Result<Message> {
            let empty: [u8; 0] = [];
            Message::new(
                MessageType::Tshare(TshareMessageType::Ready),
                tshare_identifier,
                self.id(),
                self.id(),
                &empty,
            )
        }
    }

    /// Delivers all messages into their respective participant's inboxes.
    fn deliver_all(
        messages: &[Message],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    ) {
        for message in messages {
            inboxes
                .get_mut(&message.to())
                .unwrap()
                .push(message.clone());
        }
    }

    fn is_tshare_done(quorum: &[TshareParticipant]) -> bool {
        for participant in quorum {
            if *participant.status() != Status::TerminatedSuccessfully {
                return false;
            }
        }
        true
    }

    #[allow(clippy::type_complexity)]
    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut [TshareParticipant],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
    ) -> Option<(usize, ProcessOutcome<Output>)> {
        // Pick a random participant to process
        let index = rng.gen_range(0..quorum.len());
        let participant = quorum.get_mut(index).unwrap();

        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        if inbox.is_empty() {
            // No messages to process for this participant, so pick another participant
            return None;
        }
        let message = inbox.remove(rng.gen_range(0..inbox.len()));
        debug!(
            "processing participant: {}, with message type: {:?} from {}",
            &participant.id(),
            &message.message_type(),
            &message.from(),
        );
        Some((index, participant.process_message(rng, &message).unwrap()))
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    fn tshare_always_produces_valid_outputs() -> Result<()> {
        for size in 2..4 {
            tshare_produces_valid_outputs(size)?;
        }
        Ok(())
    }

    fn tshare_produces_valid_outputs(quorum_size: usize) -> Result<()> {
        let mut rng = init_testing_with_seed(Default::default());
        let sid = Identifier::random(&mut rng);
        let mut quorum = TshareParticipant::new_quorum(sid, quorum_size, &mut rng)?;
        let mut inboxes = HashMap::new();
        for participant in &quorum {
            let _ = inboxes.insert(participant.id(), vec![]);
        }

        let inputs = quorum.iter().map(|p| p.input.clone()).collect::<Vec<_>>();

        let mut outputs = std::iter::repeat_with(|| None)
            .take(quorum_size)
            .collect::<Vec<_>>();

        for participant in &quorum {
            let inbox = inboxes.get_mut(&participant.id()).unwrap();
            inbox.push(participant.initialize_tshare_message(sid)?);
        }

        while !is_tshare_done(&quorum) {
            let (index, outcome) = match process_messages(&mut quorum, &mut inboxes, &mut rng) {
                None => continue,
                Some(x) => x,
            };

            // Deliver messages and save outputs
            match outcome {
                ProcessOutcome::Incomplete => {}
                ProcessOutcome::Processed(messages) => deliver_all(&messages, &mut inboxes),
                ProcessOutcome::Terminated(output) => outputs[index] = Some(output),
                ProcessOutcome::TerminatedForThisParticipant(output, messages) => {
                    deliver_all(&messages, &mut inboxes);
                    outputs[index] = Some(output);
                }
            }
        }

        // Make sure every player got an output
        let outputs: Vec<_> = outputs.into_iter().flatten().collect();
        assert_eq!(outputs.len(), quorum_size);

        // Make sure everybody agrees on the public parts.
        assert!(outputs
            .windows(2)
            .all(|o| o[0].public_key_shares() == o[1].public_key_shares()));

        // Check returned outputs
        //
        // Every participant should have a public output from every other participant
        // and, for a given participant, they should be the same in every output
        for party in quorum.iter_mut() {
            let pid = party.id();

            // Check that each participant fully completed its broadcast portion.
            if let Status::ParticipantCompletedBroadcast(participants) =
                party.broadcast_participant().status()
            {
                assert_eq!(participants.len(), party.other_ids().len());
            } else {
                panic!("Broadcast not completed!");
            }
        }

        // TODO.
        // Check that each participant's own `CoeffPublic` corresponds to their
        // `CoeffPrivate`
        for (output, pid) in outputs
            .iter()
            .zip(quorum.iter().map(ProtocolParticipant::id))
        {
            /*
            let coeff_publics = output
                .public_coeffs() // TODO
                .iter()
                .map(|coeff| coeff.as_ref())
                .collect::<Vec<_>>();
            let public_share = TshareParticipant::eval_public_share(&coeff_publics, id)?;

            let expected_public_share =
                CurvePoint::GENERATOR.multiply_by_bignum(output.private_key_share().as_ref())?;
            assert_eq!(public_share.unwrap().as_ref(), &expected_public_share);
            */
        }

        for (input, output) in inputs.iter().zip(outputs.iter()) {
            // TODO. Check the shared value has not changed.

            // All shares have changed.
            /*
            let public_shares_before = input
                .public_key_shares()
                .iter()
                .map(|key_share| serialize!(key_share.as_ref()).unwrap())
                .collect::<HashSet<_>>();

            let public_shares_after = output
                .public_key_shares()
                .iter()
                .map(|key_share| serialize!(key_share.as_ref()).unwrap())
                .collect::<HashSet<_>>();

            public_shares_before
                .intersection(&public_shares_after)
                .for_each(|_| {
                    panic!("All public key shares must change.");
                });
            */
        }

        Ok(())
    }
}
