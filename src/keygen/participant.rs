// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{InternalError, Result},
    keygen::{
        keygen_commit::{KeygenCommit, KeygenDecommit},
        keyshare::{KeySharePrivate, KeySharePublic},
    },
    local_storage::LocalStorage,
    messages::{KeygenMessageType, Message, MessageType},
    participant::{Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{ParticipantIdentifier, ProtocolType},
    run_only_once,
    utils::k256_order,
    zkp::pisch::{PiSchInput, PiSchPrecommit, PiSchProof, PiSchSecret},
    CurvePoint,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use tracing::{info, instrument};

mod storage {
    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Ready;
    impl TypeTag for Ready {
        type Value = ();
    }
    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = KeygenCommit;
    }
    pub(super) struct Decommit;
    impl TypeTag for Decommit {
        type Value = KeygenDecommit;
    }
    pub(super) struct SchnorrPrecom;
    impl TypeTag for SchnorrPrecom {
        type Value = PiSchPrecommit;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct PrivateKeyshare;
    impl TypeTag for PrivateKeyshare {
        type Value = KeySharePrivate;
    }
    pub(super) struct PublicKeyshare;
    impl TypeTag for PublicKeyshare {
        type Value = KeySharePublic;
    }
}

/// Protocol status for [`KeygenParticipant`].
#[derive(Debug, PartialEq)]
pub enum Status {
    Initialized,
    TerminatedSuccessfully,
}

/// A [`ProtocolParticipant`] that runs the key generation protocol[^cite].
///
/// # Protocol input
/// The protocol takes no input.
///
/// # Protocol output
/// Upon successful completion, the participant outputs the following:
/// - A [`Vec`] of [`KeySharePublic`]s, which correspond to the public keyshares
///   of each participant (including this participant), and
/// - A single [`KeySharePrivate`], which corresponds to the **private**
///   keyshare of this participant.
///
/// # ⚠️ Storage requirements
/// The [`KeySharePrivate`] output requires secure persistent storage.
///
/// [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
/// Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
/// with Identifiable Aborts. [EPrint archive,
/// 2021](https://eprint.iacr.org/2021/060.pdf). Figure 5.
#[derive(Debug)]
pub struct KeygenParticipant {
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

impl ProtocolParticipant for KeygenParticipant {
    type Input = ();
    // The output type includes public key shares `KeySharePublic` for all
    // participants (including ourselves) and `KeySharePrivate` for ourselves.
    type Output = (Vec<KeySharePublic>, KeySharePrivate);
    type Status = Status;

    fn new(id: ParticipantIdentifier, other_participant_ids: Vec<ParticipantIdentifier>) -> Self {
        Self {
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: Default::default(),
            broadcast_participant: BroadcastParticipant::new(id, other_participant_ids),
            status: Status::Initialized,
        }
    }

    fn ready_type() -> MessageType {
        MessageType::Keygen(KeygenMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Keygen
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Self::Input,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing keygen message.");

        if *self.status() == Status::TerminatedSuccessfully {
            return Err(InternalError::ProtocolAlreadyTerminated);
        }

        match message.message_type() {
            MessageType::Keygen(KeygenMessageType::R1CommitHash) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_msg, rng, input)
            }
            MessageType::Keygen(KeygenMessageType::Ready) => self.handle_ready_msg(rng, message),
            MessageType::Keygen(KeygenMessageType::R2Decommit) => {
                self.handle_round_two_msg(rng, message, input)
            }
            MessageType::Keygen(KeygenMessageType::R3Proof) => {
                self.handle_round_three_msg(rng, message, input)
            }
            MessageType::Keygen(_) => Err(InternalError::MessageMustBeBroadcasted)?,
            _ => Err(InternalError::MisroutedMessage)?,
        }
    }

    fn status(&self) -> &Self::Status {
        &self.status
    }
}

impl InnerProtocolParticipant for KeygenParticipant {
    type Context = ();

    fn retrieve_context(&self) -> &Self::Context {
        &()
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.local_storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.local_storage
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &Vec<ParticipantIdentifier> {
        &self.other_participant_ids
    }
}

impl Broadcast for KeygenParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl KeygenParticipant {
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling ready keygen message.");

        let (ready_outcome, is_ready) = self.process_ready_message::<storage::Ready>(message)?;

        if is_ready {
            let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, message))?;

            Ok(ready_outcome.with_messages(round_one_messages))
        } else {
            Ok(ready_outcome)
        }
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round one keygen messages.");

        let (keyshare_private, keyshare_public) = new_keyshare(self.id(), rng)?;
        self.local_storage
            .store::<storage::PrivateKeyshare>(self.id, keyshare_private);
        self.local_storage
            .store::<storage::PublicKeyshare>(self.id, keyshare_public.clone());

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);
        let X = keyshare_public.X;

        // todo: maybe there should be a function for generating a PiSchInput
        let input = PiSchInput::new(&g, &q, &X);
        let sch_precom = PiSchProof::precommit(rng, &input)?;
        let decom =
            KeygenDecommit::new(rng, &message.id(), &self.id, &keyshare_public, &sch_precom);
        let com = decom.commit()?;
        let com_bytes = &serialize!(&com)?;

        self.local_storage.store::<storage::Commit>(self.id, com);
        self.local_storage
            .store::<storage::Decommit>(self.id, decom);
        self.local_storage
            .store::<storage::SchnorrPrecom>(self.id, sch_precom);

        let messages = self.broadcast(
            rng,
            MessageType::Keygen(KeygenMessageType::R1CommitHash),
            com_bytes.clone(),
            message.id(),
            BroadcastTag::KeyGenR1CommitHash,
        )?;
        Ok(messages)
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: &BroadcastOutput,
        input: &(),
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round one keygen message.");

        if broadcast_message.tag != BroadcastTag::KeyGenR1CommitHash {
            return Err(InternalError::IncorrectBroadcastMessageTag);
        }
        let message = &broadcast_message.msg;
        self.local_storage
            .store::<storage::Commit>(message.from(), KeygenCommit::from_message(message)?);

        // check if we've received all the commits.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(&self.other_participant_ids);

        if r1_done {
            // Finish round 1 by generating messages for round 2
            let round_one_messages = run_only_once!(self.gen_round_two_msgs(rng, message))?;

            // Process any round 2 messages we may have received early
            let round_two_outcomes = self
                .fetch_messages(MessageType::Keygen(KeygenMessageType::R2Decommit))?
                .iter()
                .map(|msg| self.handle_round_two_msg(rng, msg, input))
                .collect::<Result<Vec<_>>>()?;

            ProcessOutcome::collect_with_messages(round_two_outcomes, round_one_messages)
        } else {
            // Otherwise, wait for more round 1 messages
            Ok(ProcessOutcome::Incomplete)
        }
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round two keygen messages.");

        let mut messages = vec![];
        // check that we've generated our keyshare before trying to retrieve it
        if !self
            .local_storage
            .contains::<storage::PublicKeyshare>(self.id)
        {
            let more_messages = run_only_once!(self.gen_round_one_msgs(rng, message))?;
            messages.extend_from_slice(&more_messages);
        }

        let decom = self.local_storage.retrieve::<storage::Decommit>(self.id)?;
        let decom_bytes = serialize!(&decom)?;
        let more_messages: Vec<Message> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Keygen(KeygenMessageType::R2Decommit),
                    message.id(),
                    self.id,
                    other_participant_id,
                    &decom_bytes,
                )
            })
            .collect();
        messages.extend_from_slice(&more_messages);
        Ok(messages)
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &(),
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round two keygen message.");
        // We must receive all commitments in round 1 before we start processing
        // decommits in round 2.
        let r1_done = self.local_storage.contains_for_all_ids::<storage::Commit>(
            &[self.other_participant_ids.clone(), vec![self.id]].concat(),
        );
        if !r1_done {
            // Store any early round 2 messages
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        let decom = KeygenDecommit::from_message(message)?;
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(message.from())?;
        decom.verify(&message.id(), &message.from(), com)?;
        self.local_storage
            .store::<storage::Decommit>(message.from(), decom);

        // Check if we've received all the decommits
        let r2_done = self
            .local_storage
            .contains_for_all_ids::<storage::Decommit>(&self.other_participant_ids);

        if r2_done {
            // Generate messages for round 3...
            let round_two_messages = run_only_once!(self.gen_round_three_msgs(rng, message))?;

            // ...and handle any messages that other participants have sent for round 3.
            let round_three_outcomes = self
                .fetch_messages(MessageType::Keygen(KeygenMessageType::R3Proof))?
                .iter()
                .map(|msg| self.handle_round_three_msg(rng, msg, input))
                .collect::<Result<Vec<_>>>()?;
            ProcessOutcome::collect_with_messages(round_three_outcomes, round_two_messages)
        } else {
            // Otherwise, wait for more round 2 messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round three keygen messages.");

        let rids: Vec<[u8; 32]> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                let decom = self
                    .local_storage
                    .retrieve::<storage::Decommit>(other_participant_id)?;
                Ok(decom.rid)
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let my_decom = self.local_storage.retrieve::<storage::Decommit>(self.id)?;
        let mut global_rid = my_decom.rid;
        // xor all the rids together. In principle, many different options for combining
        // these should be okay
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.local_storage
            .store::<storage::GlobalRid>(self.id, global_rid);

        let mut transcript = Transcript::new(b"keygen schnorr");
        transcript.append_message(b"rid", &serialize!(&global_rid)?);
        let precom = self
            .local_storage
            .retrieve::<storage::SchnorrPrecom>(self.id)?;

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);
        let my_pk = self
            .local_storage
            .retrieve::<storage::PublicKeyshare>(self.id)?;
        let input = PiSchInput::new(&g, &q, &my_pk.X);

        let my_sk = self
            .local_storage
            .retrieve::<storage::PrivateKeyshare>(self.id)?;

        let proof = PiSchProof::prove_from_precommit(
            precom,
            &input,
            &PiSchSecret::new(&my_sk.x),
            &transcript,
        )?;
        let proof_bytes = serialize!(&proof)?;

        let more_messages: Vec<Message> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Keygen(KeygenMessageType::R3Proof),
                    message.id(),
                    self.id,
                    other_participant_id,
                    &proof_bytes,
                )
            })
            .collect();
        Ok(more_messages)
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        _input: &(),
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round three keygen message.");

        if self
            .local_storage
            .retrieve::<storage::GlobalRid>(self.id)
            .is_err()
        {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        let proof = PiSchProof::from_message(message)?;
        let global_rid = self.local_storage.retrieve::<storage::GlobalRid>(self.id)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);
        let input = PiSchInput::new(&g, &q, &decom.pk.X);

        let mut transcript = Transcript::new(b"keygen schnorr");
        transcript.append_message(b"rid", &serialize!(&global_rid)?);

        proof.verify_with_transcript(&input, &transcript)?;
        let keyshare = decom.get_keyshare();
        self.local_storage
            .store::<storage::PublicKeyshare>(message.from(), keyshare.clone());

        //check if we've stored all the public keyshares
        let keyshare_done = self
            .local_storage
            .contains_for_all_ids::<storage::PublicKeyshare>(&self.all_participants());

        // If so, we completed the protocol! Return the outputs.
        if keyshare_done {
            let public_key_shares = self
                .all_participants()
                .iter()
                .map(|pid| {
                    let value = self
                        .local_storage
                        .retrieve::<storage::PublicKeyshare>(*pid)?;
                    Ok(value.clone())
                })
                .collect::<Result<Vec<_>>>()?;
            let private_key_share = self
                .local_storage
                .retrieve::<storage::PrivateKeyshare>(self.id)?;
            self.status = Status::TerminatedSuccessfully;
            Ok(ProcessOutcome::Terminated((
                public_key_shares,
                private_key_share.clone(),
            )))
        } else {
            // Otherwise, we'll have to wait for more round three messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }
}

/// Generates a new [KeySharePrivate] and [KeySharePublic]
fn new_keyshare<R: RngCore + CryptoRng>(
    participant: ParticipantIdentifier,
    rng: &mut R,
) -> Result<(KeySharePrivate, KeySharePublic)> {
    let order = k256_order();
    let private_share = BigNumber::from_rng(&order, rng);
    let g = CurvePoint::GENERATOR;
    let public_share = CurvePoint(g.0 * crate::utils::bn_to_scalar(&private_share)?);

    Ok((
        KeySharePrivate { x: private_share },
        KeySharePublic::new(participant, public_share),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utils::testing::init_testing, Identifier};
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::HashMap;
    use tracing::debug;

    impl KeygenParticipant {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            quorum_size: usize,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            let mut participant_ids = vec![];
            for _ in 0..quorum_size {
                participant_ids.push(ParticipantIdentifier::random(rng));
            }
            let participants = participant_ids
                .iter()
                .map(|&participant_id| -> KeygenParticipant {
                    // Filter out current participant id from list of other ids
                    let mut other_ids = vec![];
                    for &id in participant_ids.iter() {
                        if id != participant_id {
                            other_ids.push(id);
                        }
                    }
                    Self::new(participant_id, other_ids)
                })
                .collect::<Vec<KeygenParticipant>>();
            Ok(participants)
        }
        pub fn initialize_keygen_message(&self, keygen_identifier: Identifier) -> Message {
            Message::new(
                MessageType::Keygen(KeygenMessageType::Ready),
                keygen_identifier,
                self.id,
                self.id,
                &[],
            )
        }
    }

    /// Delivers all messages into their respective participant's inboxes
    fn deliver_all(
        messages: &[Message],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    ) -> Result<()> {
        for message in messages {
            for (&id, inbox) in &mut *inboxes {
                if id == message.to() {
                    inbox.push(message.clone());
                    break;
                }
            }
        }
        Ok(())
    }

    fn is_keygen_done(quorum: &[KeygenParticipant]) -> bool {
        for participant in quorum {
            if *participant.status() != Status::TerminatedSuccessfully {
                return false;
            }
        }
        true
    }

    #[allow(clippy::type_complexity)]
    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut Vec<KeygenParticipant>,
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
    ) -> Option<(
        usize,
        ProcessOutcome<(Vec<KeySharePublic>, KeySharePrivate)>,
    )> {
        // Pick a random participant to process
        let index = rng.gen_range(0..quorum.len());
        let participant = quorum.get_mut(index).unwrap();

        let inbox = inboxes.get_mut(&participant.id).unwrap();
        if inbox.is_empty() {
            // No messages to process for this participant, so pick another participant
            return None;
        }
        let message = inbox.remove(rng.gen_range(0..inbox.len()));
        debug!(
            "processing participant: {}, with message type: {:?} from {}",
            &participant.id,
            &message.message_type(),
            &message.from(),
        );
        Some((
            index,
            participant.process_message(rng, &message, &()).unwrap(),
        ))
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    // This test is cheap. Try a bunch of message permutations to decrease error
    // likelihood
    fn keygen_always_produces_valid_outputs() -> Result<()> {
        let _rng = init_testing();

        for _ in 0..20 {
            keygen_produces_valid_outputs()?;
        }
        Ok(())
    }
    #[test]
    fn keygen_produces_valid_outputs() -> Result<()> {
        let QUORUM_SIZE = 3;
        let mut rng = init_testing();
        let mut quorum = KeygenParticipant::new_quorum(QUORUM_SIZE, &mut rng)?;
        let mut inboxes = HashMap::new();
        for participant in &quorum {
            let _ = inboxes.insert(participant.id, vec![]);
        }
        let mut outputs = std::iter::repeat_with(|| None)
            .take(QUORUM_SIZE)
            .collect::<Vec<_>>();

        let keyshare_identifier = Identifier::random(&mut rng);

        for participant in &quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_keygen_message(keyshare_identifier));
        }
        while !is_keygen_done(&quorum) {
            let (index, outcome) = match process_messages(&mut quorum, &mut inboxes, &mut rng) {
                None => continue,
                Some(x) => x,
            };

            // Deliver messages and save outputs
            match outcome {
                ProcessOutcome::Incomplete => {}
                ProcessOutcome::Processed(messages) => deliver_all(&messages, &mut inboxes)?,
                ProcessOutcome::Terminated(output) => outputs[index] = Some(output),
                ProcessOutcome::TerminatedForThisParticipant(output, messages) => {
                    deliver_all(&messages, &mut inboxes)?;
                    outputs[index] = Some(output);
                }
            }
        }

        // Make sure every player got an output
        let outputs: Vec<_> = outputs.into_iter().flatten().collect();
        assert!(outputs.len() == QUORUM_SIZE);

        // Check returned outputs
        //
        // Every participant should have a public output from every other participant
        // and, for a given participant, they should be the same in every output
        for party in quorum.iter_mut() {
            let pid = party.id;

            // Collect the KeySharePublic associated with pid from every output
            let mut publics_for_pid = vec![];
            for (publics, _) in &outputs {
                let key_share = publics
                    .iter()
                    .find(|key_share| key_share.participant() == pid);

                // Make sure every participant had a key share for this pid
                assert!(key_share.is_some());
                publics_for_pid.push(key_share.unwrap());
            }

            // Make sure they're all equal
            assert!(publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]));

            // Check that each participant fully completed its broadcast portion.
            if let crate::broadcast::participant::Status::ParticipantCompletedBroadcast(
                participants,
            ) = party.broadcast_participant().status()
            {
                assert_eq!(participants.len(), party.other_participant_ids.len());
            } else {
                panic!("Broadcast not completed!");
            }
        }

        // Check that each participant's own `PublicKeyshare` corresponds to their
        // `PrivateKeyshare`
        for ((publics, private), pid) in outputs.iter().zip(quorum.iter().map(|p| p.id())) {
            let public_share = publics
                .iter()
                .find(|public_share| public_share.participant() == pid);
            assert!(public_share.is_some());

            let expected_public_share =
                CurvePoint(CurvePoint::GENERATOR.0 * crate::utils::bn_to_scalar(&private.x)?);
            assert_eq!(public_share.unwrap().X, expected_public_share);
        }

        Ok(())
    }
}
