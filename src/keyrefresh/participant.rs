//! Types and functions related to the key refresh sub-protocol Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{CallerError, InternalError, Result},
    keyrefresh::{
        keyrefresh_commit::{KeyrefreshCommit, KeyrefreshDecommit},
        keyshare::{KeyUpdateEncrypted, KeyUpdatePrivate, KeyUpdatePublic},
    },
    local_storage::LocalStorage,
    messages::{KeyrefreshMessageType, Message, MessageType},
    participant::{
        Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant, Status,
    },
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    run_only_once,
    zkp::pisch::{CommonInput, PiSchPrecommit, PiSchProof, ProverSecret},
    Identifier, ParticipantConfig,
};

use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use tracing::{error, info, instrument, warn};

use super::{input::Input, Output};

mod storage {
    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = KeyrefreshCommit;
    }
    pub(super) struct Decommit;
    impl TypeTag for Decommit {
        type Value = KeyrefreshDecommit;
    }
    pub(super) struct VecSchnorrPrecom;
    impl TypeTag for VecSchnorrPrecom {
        type Value = Vec<PiSchPrecommit>;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct PrivateUpdatesForOthers;
    impl TypeTag for PrivateUpdatesForOthers {
        type Value = Vec<super::KeyUpdatePrivate>;
    }
    pub(super) struct ValidPublicUpdates;
    impl TypeTag for ValidPublicUpdates {
        type Value = Vec<super::KeyUpdatePublic>;
    }
    pub(super) struct ValidPrivateUpdate;
    impl TypeTag for ValidPrivateUpdate {
        type Value = super::KeyUpdatePrivate;
    }
}

/**
A [`ProtocolParticipant`] that runs the key refresh protocol[^cite].

# Protocol input
- Encryption and decryption keys from the Aux-Info protocol.

# Protocol output
Upon successful completion, the participant produces [`Output`], which
includes:
- A list of *updated* public key shares, one for each participant (including this
  participant);
- A single *updated* private key share for this participant.

# 🔒 Storage requirements
The [private key share](crate::keygen::KeySharePrivate) in the output requires secure
persistent storage.

# High-level protocol description
The key refresh protocol runs in three rounds:

**Round 1**
Each participant i samples a private key update x_ij for each other
  participant j. The sum of updates must equal 0. It computes the public key updates X_ij. It prepares a Schnorr message A_i. It broadcasts a commitment to V_i to all its X_ij, A_i, and a blinding factor u_i.

**Round 2**
Once all commitments have been received, the second round sees each participant open its commitment by broadcasting its X_ij, A_i, u_i.

**Round 3**
Each participant verifies the received values against the commitments. Then, each participant verifies that the public updates from each other participant sum to the identity point. In the third round, each participant computes a Schnorr proof of knowledge of its private updates x_ij, continuing from its earlier message A_i. Each participant i encrypts the private updates x_ij to their respective recipients j, using the encryption keys from the Aux-Info protocol. Each participant broadcasts the proofs and the ciphertexts to all other participants.

**Output**
Each participant verifies the proofs of knowledge, and the consistency with the A_j from round 2. Then, each participant i decrypts the updates x_ji received from other participants j, and verifies their consistency with X_ji from round 2. Each participant i computes its updated private key share x_i by adding to it its received updates x_ji. Each participant i computes its updated view of all public key shares X_j by adding to them the corresponding public updates X_ij.


[^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
with Identifiable Aborts. [EPrint archive,
2021](https://eprint.iacr.org/2021/060.pdf). Figure 6.
*/
#[derive(Debug)]
pub struct KeyrefreshParticipant {
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

impl ProtocolParticipant for KeyrefreshParticipant {
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
        MessageType::Keyrefresh(KeyrefreshMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Keyrefresh
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

    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "KEYREFRESH: Player {}: received {:?} from {}",
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
            MessageType::Keyrefresh(KeyrefreshMessageType::Ready) => {
                self.handle_ready_msg(rng, message)
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R1CommitHash) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_msg, rng)
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit) => {
                self.handle_round_two_msg(rng, message)
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs) => {
                self.handle_round_three_msg(message)
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R3PrivateUpdate) => {
                self.handle_round_three_msg_private(message)
            }
            message_type => {
                error!(
                    "Incorrect MessageType given to KeyrefreshParticipant. Got: {:?}",
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

impl InnerProtocolParticipant for KeyrefreshParticipant {
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

impl Broadcast for KeyrefreshParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl KeyrefreshParticipant {
    /// Handle "Ready" messages from the protocol participants.
    ///
    /// Once "Ready" messages have been received from all participants, this
    /// method will trigger this participant to generate its round one message.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling ready keyrefresh message.");

        let ready_outcome = self.process_ready_message(rng, message)?;
        let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, message.id()))?;
        // extend the output with r1 messages (if they hadn't already been generated)
        Ok(ready_outcome.with_messages(round_one_messages))
    }

    /// Generate the protocol's round one message.
    ///
    /// The outcome is a broadcast message containing a commitment to:
    /// - updates [`KeyUpdatePublic`] X_ij for all other participants,
    /// - a "pre-commitment" A to a Schnorr proof.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one keyrefresh messages.");

        // Generate keyshare updates for all participants.
        let (update_privates, update_publics) = {
            let mut privates = vec![];
            let mut publics = vec![];

            // Random shares for others.
            for pid in self.other_ids() {
                let (private, public) = KeyUpdatePublic::new_keyshare(*pid, rng)?;
                privates.push(private);
                publics.push(public);
            }

            // Compute one's own update such that the sum of updates is 0.
            let my_update_private = KeyUpdatePrivate::zero_sum(&privates);
            let my_update_public =
                KeyUpdatePublic::new(self.id(), my_update_private.public_point()?);
            privates.push(my_update_private);
            publics.push(my_update_public);

            (privates, publics)
        };

        // This corresponds to `A_ij` in the paper.
        let sch_precoms = (0..update_publics.len())
            .map(|_| PiSchProof::precommit(rng))
            .collect::<Result<Vec<_>>>()?;

        let decom = KeyrefreshDecommit::new(
            rng,
            &sid,
            &self.id(),
            update_publics,
            sch_precoms
                .iter()
                .map(|sch_precom| *sch_precom.precommitment())
                .collect(),
        );

        // Store the beginning of our proofs so we can continue the proofs later.
        self.local_storage
            .store::<storage::VecSchnorrPrecom>(self.id(), sch_precoms);

        // Mark our own public updates as verified.
        self.local_storage
            .store::<storage::ValidPublicUpdates>(self.id(), decom.update_publics.clone());

        // Store the private update from ourselves to ourselves.
        self.local_storage.store::<storage::ValidPrivateUpdate>(
            self.id(),
            update_privates[update_privates.len() - 1].clone(),
        );

        // Store the private updates from us to others so we can share them later.
        self.local_storage
            .store::<storage::PrivateUpdatesForOthers>(self.id(), update_privates);

        // Mark our own commitment as ready. This corresponds to `V_i` in the paper.
        let com = decom.commit()?;
        let com_bytes = serialize!(&com)?;
        self.local_storage.store::<storage::Commit>(self.id(), com);

        // Store our committed values so we can open the commitment later.
        self.local_storage
            .store::<storage::Decommit>(self.id(), decom);

        let messages = self.broadcast(
            rng,
            MessageType::Keyrefresh(KeyrefreshMessageType::R1CommitHash),
            com_bytes,
            sid,
            BroadcastTag::KeyRefreshR1CommitHash,
        )?;
        Ok(messages)
    }

    /// Handle round one messages from the protocol participants.
    ///
    /// In round one, each participant broadcasts its commitment to its public
    /// key share and a "precommitment" to a Schnorr proof. Once all such
    /// commitments have been received, this participant will send an opening of
    /// its own commitment to all other parties.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: BroadcastOutput,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        let message = broadcast_message.into_message(BroadcastTag::KeyRefreshR1CommitHash)?;

        self.check_for_duplicate_msg::<storage::Commit>(message.from())?;
        info!("Handling round one keyrefresh message.");

        let keyrefresh_commit = KeyrefreshCommit::from_message(&message)?;
        self.local_storage
            .store_once::<storage::Commit>(message.from(), keyrefresh_commit)?;

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
                .fetch_messages(MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit))?
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
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two keyrefresh messages.");

        let mut messages = vec![];
        // Check that we've generated our keyshare before trying to retrieve it.
        //
        // Because we are not checking `self.all_participants` in
        // `handle_round_one_msg`, we may reach this point and not actually have
        // generated round one messages for ourselves (in particular,
        // `PublicKeyshare` and `Decommit`). This check forces that behavior.
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
            MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit),
            decom,
        )?;
        messages.extend_from_slice(&more_messages);
        Ok(messages)
    }

    /// Handle the protocol's round two messages.
    ///
    /// Here we check that the decommitments from each participant are valid.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::Decommit>(message.from())?;
        info!("Handling round two keyrefresh message.");

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
        let decom = KeyrefreshDecommit::from_message(message, com, &self.all_participants())?;
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
                .fetch_messages(MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs))?
                .iter()
                .map(|msg| self.handle_round_three_msg(msg))
                .collect::<Result<Vec<_>>>()?;

            let outcomes_private = self
                .fetch_messages(MessageType::Keyrefresh(
                    KeyrefreshMessageType::R3PrivateUpdate,
                ))?
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
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>> {
        info!("Generating round three keyrefresh messages.");

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

        // Generate proofs for each update.
        let precoms = self
            .local_storage
            .retrieve::<storage::VecSchnorrPrecom>(self.id())?;

        let private_updates = self
            .local_storage
            .retrieve::<storage::PrivateUpdatesForOthers>(self.id())?;

        let mut proofs: Vec<PiSchProof> = vec![];
        for i in 0..precoms.len() {
            let pk = &decom.update_publics[i];
            let input = CommonInput::new(pk);
            let precom = &precoms[i];
            let sk = &private_updates[i];

            let proof = PiSchProof::prove_from_precommit(
                &self.retrieve_context(),
                precom,
                &input,
                &ProverSecret::new(sk.as_ref()),
                &transcript,
            )?;

            proofs.push(proof);
        }

        // Encrypt the private updates to each participant.
        let encrypted_updates = self
            .other_ids()
            .iter()
            .zip(private_updates.iter())
            .map(|(other_participant_id, update_private)| {
                let auxinfo = self.input.find_auxinfo_public(*other_participant_id)?;
                KeyUpdateEncrypted::encrypt(update_private, auxinfo.pk(), rng)
            })
            .collect::<Result<Vec<_>>>()?;

        // Send all proofs to everybody.
        let mut messages = self.message_for_other_participants(
            MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs),
            proofs,
        )?;

        // Send their private updates to each individual participant.
        messages.extend(
            self.other_ids()
                .iter()
                .zip(encrypted_updates.iter())
                .map(|(other_participant_id, encrypted_update)| {
                    Message::new(
                        MessageType::Keyrefresh(KeyrefreshMessageType::R3PrivateUpdate),
                        self.sid(),
                        self.id(),
                        *other_participant_id,
                        encrypted_update,
                    )
                })
                .collect::<Result<Vec<Message>>>()?,
        );

        Ok(messages)
    }

    /// Handle round three messages only after our own `gen_round_three_msgs`.
    fn can_handle_round_three_msg(&self) -> bool {
        self.local_storage.contains::<storage::GlobalRid>(self.id())
    }

    /// Handle the protocol's round three public messages.
    ///
    /// Here we validate the Schnorr proofs from each participant.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::ValidPublicUpdates>(message.from())?;

        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three keyrefresh broadcast message.");
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        info!("Handling round three keyrefresh broadcast message.");

        let global_rid = *self
            .local_storage
            .retrieve::<storage::GlobalRid>(self.id())?;

        let proofs = PiSchProof::from_message_multi(message)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;

        // Check that there is one proof per participant.
        if proofs.len() != self.all_participants().len() {
            error!("Received incorrect number of proofs",);
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        for ((proof, precommit), update_public) in proofs
            .into_iter()
            .zip(decom.As.iter())
            .zip(decom.update_publics.iter())
        {
            let mut transcript = schnorr_proof_transcript(self.sid(), &global_rid, message.from())?;
            proof.verify_with_precommit(
                CommonInput::new(update_public),
                &self.retrieve_context(),
                &mut transcript,
                precommit,
            )?;
        }

        // Only if the proof verifies do we store the participant's updates.
        self.local_storage
            .store_once::<storage::ValidPublicUpdates>(
                message.from(),
                decom.update_publics.clone(),
            )?;

        self.maybe_finish()
    }

    /// Handle the protocol's round three private messages.
    ///
    /// Here we validate and store a private update from someone to us.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg_private(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::ValidPrivateUpdate>(message.from())?;

        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three keyrefresh private message.");
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        info!("Handling round three keyrefresh private message.");

        message.check_type(MessageType::Keyrefresh(
            KeyrefreshMessageType::R3PrivateUpdate,
        ))?;
        let encrypted_update: KeyUpdateEncrypted = deserialize!(&message.unverified_bytes)?;

        // Get my private key from the AuxInfo protocol.
        let my_dk = self.input.private_auxinfo().decryption_key();

        // Decrypt the private update.
        let update_private = encrypted_update.decrypt(my_dk)?;

        // Check that this private share matches our public share in KeyrefreshDecommit
        // from this participant.
        let implied_public = update_private.public_point()?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;
        let expected_public = decom
            .update_publics
            .iter()
            .find(|kup| kup.participant() == self.id())
            .ok_or(InternalError::InternalInvariantFailed)?
            .as_ref();
        if &implied_public != expected_public {
            error!("the private update does not match the public update");
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        self.local_storage
            .store::<storage::ValidPrivateUpdate>(message.from(), update_private);

        self.maybe_finish()
    }

    fn maybe_finish(&mut self) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        // Have we validated and stored the public updates from everybody to everybody?
        let got_all_public_updates = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPublicUpdates>(&self.all_participants());

        // Have we got the private updates from everybody to us?
        let got_all_private_updates = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPrivateUpdate>(&self.all_participants());

        // If so, we completed the protocol! Return the outputs.
        if got_all_public_updates && got_all_private_updates {
            // Compute the update to the public key share of each participant.
            let from_all_to_all_public = self
                .all_participants()
                .iter()
                .map(|pid| {
                    self.local_storage
                        .remove::<storage::ValidPublicUpdates>(*pid)
                })
                .collect::<Result<Vec<_>>>()?;
            let all_public_updates =
                Self::aggregate_public_updates(&self.all_participants(), &from_all_to_all_public)?;

            // Apply the updates to everybody's public key shares.
            let new_public_shares = self
                .input
                .public_key_shares()
                .iter()
                .map(|current_pk| {
                    let pk_update = all_public_updates
                        .iter()
                        .find(|update| update.participant() == current_pk.participant())
                        .ok_or(InternalError::InternalInvariantFailed)?;

                    Ok(pk_update.apply(current_pk))
                })
                .collect::<Result<Vec<_>>>()?;

            // Compute the update to one's own private key share.
            let from_all_to_me_private = self
                .all_participants()
                .iter()
                .map(|pid| {
                    self.local_storage
                        .remove::<storage::ValidPrivateUpdate>(*pid)
                })
                .collect::<Result<Vec<_>>>()?;
            let my_private_update = Self::aggregate_private_updates(&from_all_to_me_private);

            // Apply the update to my private key share.
            let my_new_share = my_private_update.apply(self.input.private_key_share());

            // Return the output and stop.
            let rid_before = *self.input.keygen_output().rid();
            let chain_code_before = *self.input.keygen_output().chain_code();
            let output = Output::from_parts(
                new_public_shares,
                my_new_share,
                rid_before,
                chain_code_before,
            )?;

            // Final validation that the public key of the quorum has not changed. This
            // should never fail because this is already verified in round 2 by
            // `KeyrefreshDecommit::from_message`.
            let pk_before = self.input.keygen_output().public_key()?;
            let pk_after = output.public_key()?;
            if pk_before != pk_after {
                error!("Keyrefresh output did not preserve the quorum public key.");
                return Err(InternalError::InternalInvariantFailed);
            }

            self.status = Status::TerminatedSuccessfully;
            Ok(ProcessOutcome::Terminated(output))
        } else {
            // Otherwise, we'll have to wait for more round three messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    fn aggregate_private_updates(update_privates: &[KeyUpdatePrivate]) -> KeyUpdatePrivate {
        KeyUpdatePrivate::sum(update_privates)
    }

    fn aggregate_public_updates(
        participants: &[ParticipantIdentifier],
        from_all_to_all: &[Vec<KeyUpdatePublic>],
    ) -> Result<Vec<KeyUpdatePublic>> {
        participants
            .iter()
            .map(|p_i| {
                let from_all_to_i = Self::find_updates_for_participant(*p_i, from_all_to_all)?;

                let sum_for_i = KeyUpdatePublic::sum(*p_i, &from_all_to_i);
                Ok(sum_for_i)
            })
            .collect()
    }

    fn find_updates_for_participant(
        p_i: ParticipantIdentifier,
        from_all_to_all: &[Vec<KeyUpdatePublic>],
    ) -> Result<Vec<KeyUpdatePublic>> {
        let from_all_to_i = from_all_to_all
            .iter()
            .map(|from_j_to_all| {
                let from_j_to_i = from_j_to_all
                    .iter()
                    .find(|from_j_to_x| from_j_to_x.participant() == p_i)
                    .cloned()
                    .ok_or(InternalError::InternalInvariantFailed);
                from_j_to_i
            })
            .collect();
        from_all_to_i
    }
}

/// Generate a [`Transcript`] for [`PiSchProof`].
fn schnorr_proof_transcript(
    sid: Identifier,
    global_rid: &[u8; 32],
    sender_id: ParticipantIdentifier,
) -> Result<Transcript> {
    let mut transcript = Transcript::new(b"keyrefresh schnorr");
    transcript.append_message(b"sid", &serialize!(&sid)?);
    transcript.append_message(b"rid", &serialize!(global_rid)?);
    transcript.append_message(b"sender_id", &serialize!(&sender_id)?);
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auxinfo, keygen,
        keyrefresh::input::Input,
        utils::{testing::init_testing, CurvePoint},
        Identifier, ParticipantConfig,
    };
    use rand::{CryptoRng, Rng, RngCore};
    use std::{
        collections::{HashMap, HashSet},
        iter::zip,
    };
    use tracing::debug;

    impl KeyrefreshParticipant {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            quorum_size: usize,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            // Prepare prereqs for making KeyRefreshParticipant's. Assume all the
            // simulations are stable (e.g. keep config order)
            let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
            let keygen_outputs = keygen::Output::simulate_set(&configs, rng);
            let auxinfo_outputs = auxinfo::Output::simulate_set(&configs, rng);

            // Make the participants
            zip(configs, zip(keygen_outputs.clone(), auxinfo_outputs))
                .map(|(config, (keygen_output, auxinfo_output))| {
                    let input = Input::new(auxinfo_output, keygen_output)?;
                    Self::new(sid, config.id(), config.other_ids().to_vec(), input)
                })
                .collect::<Result<Vec<_>>>()
        }

        pub fn initialize_keyrefresh_message(
            &self,
            keyrefresh_identifier: Identifier,
        ) -> Result<Message> {
            let empty: [u8; 0] = [];
            Message::new(
                MessageType::Keyrefresh(KeyrefreshMessageType::Ready),
                keyrefresh_identifier,
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

    fn is_keyrefresh_done(quorum: &[KeyrefreshParticipant]) -> bool {
        for participant in quorum {
            if *participant.status() != Status::TerminatedSuccessfully {
                return false;
            }
        }
        true
    }

    #[allow(clippy::type_complexity)]
    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut [KeyrefreshParticipant],
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
    fn keyrefresh_always_produces_valid_outputs() -> Result<()> {
        for size in 2..12 {
            keyrefresh_produces_valid_outputs(size)?;
        }
        Ok(())
    }

    fn keyrefresh_produces_valid_outputs(quorum_size: usize) -> Result<()> {
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let mut quorum = KeyrefreshParticipant::new_quorum(sid, quorum_size, &mut rng)?;
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
            inbox.push(participant.initialize_keyrefresh_message(sid)?);
        }

        while !is_keyrefresh_done(&quorum) {
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

        // Check returned outputs
        //
        // Every participant should have a public output from every other participant
        // and, for a given participant, they should be the same in every output
        for party in quorum.iter_mut() {
            let pid = party.id();

            // Collect the KeySharePublic associated with pid from every output
            let mut publics_for_pid = vec![];
            for output in &outputs {
                let key_share = output
                    .public_key_shares()
                    .iter()
                    .find(|key_share| key_share.participant() == pid);

                // Make sure every participant had a key share for this pid
                assert!(key_share.is_some());
                publics_for_pid.push(key_share.unwrap());
            }

            // Make sure they're all equal
            assert!(publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]));

            // Check that each participant fully completed its broadcast portion.
            if let Status::ParticipantCompletedBroadcast(participants) =
                party.broadcast_participant().status()
            {
                assert_eq!(participants.len(), party.other_ids().len());
            } else {
                panic!("Broadcast not completed!");
            }
        }

        // Check that each participant's own `PublicKeyshare` corresponds to their
        // `PrivateKeyshare`
        for (output, pid) in outputs
            .iter()
            .zip(quorum.iter().map(ProtocolParticipant::id))
        {
            let public_share = output
                .public_key_shares()
                .iter()
                .find(|public_share| public_share.participant() == pid);
            assert!(public_share.is_some());

            let expected_public_share =
                CurvePoint::GENERATOR.multiply_by_bignum(output.private_key_share().as_ref())?;
            assert_eq!(public_share.unwrap().as_ref(), &expected_public_share);
        }

        for (input, output) in inputs.iter().zip(outputs.iter()) {
            // The public key of the quorum has not changed.
            let pk_before = input.keygen_output().public_key()?;
            let pk_after = output.public_key()?;
            assert_eq!(pk_before, pk_after);

            // All key shares have changed.
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

            // The rid has not changed.
            assert_eq!(input.keygen_output().rid(), output.rid());
        }

        Ok(())
    }
}
