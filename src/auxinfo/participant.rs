// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::{
        auxinfo_commit::{AuxInfoCommit, AuxInfoDecommit},
        info::{AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses},
        proof::AuxInfoProof,
    },
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{InternalError, Result},
    local_storage::LocalStorage,
    messages::{AuxinfoMessageType, Message, MessageType},
    paillier::DecryptionKey,
    participant::{Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{ParticipantIdentifier, ProtocolType},
    ring_pedersen::VerifiedRingPedersen,
    run_only_once,
};
use rand::{CryptoRng, RngCore};
use tracing::{debug, info, instrument};

// Local storage data types.
mod storage {
    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Ready;
    impl TypeTag for Ready {
        type Value = ();
    }
    pub(super) struct Private;
    impl TypeTag for Private {
        type Value = AuxInfoPrivate;
    }
    pub(super) struct Public;
    impl TypeTag for Public {
        type Value = AuxInfoPublic;
    }
    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = AuxInfoCommit;
    }
    pub(super) struct Decommit;
    impl TypeTag for Decommit {
        type Value = AuxInfoDecommit;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct Witnesses;
    impl TypeTag for Witnesses {
        type Value = AuxInfoWitnesses;
    }
}

/// A participant that runs the auxiliary information protocol.
///
/// Note that this does not include the key-refresh steps included in the
/// original paper specification.
#[derive(Debug)]
pub struct AuxInfoParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    /// Broadcast subprotocol handler
    broadcast_participant: BroadcastParticipant,
}

impl ProtocolParticipant for AuxInfoParticipant {
    type Input = ();
    // The output type includes `AuxInfoPublic` material for all participants
    // (including ourselves) and `AuxInfoPrivate` for ourselves.
    type Output = (Vec<AuxInfoPublic>, AuxInfoPrivate);

    fn new(id: ParticipantIdentifier, other_participant_ids: Vec<ParticipantIdentifier>) -> Self {
        Self {
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: Default::default(),
            broadcast_participant: BroadcastParticipant::new(id, other_participant_ids),
        }
    }

    fn ready_type() -> MessageType {
        MessageType::Auxinfo(AuxinfoMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::AuxInfo
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Self::Input,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing auxinfo message.");

        match message.message_type() {
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_msg, rng, input)
            }
            MessageType::Auxinfo(AuxinfoMessageType::Ready) => self.handle_ready_msg(rng, message),
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit) => {
                self.handle_round_two_msg(rng, message, input)
            }
            MessageType::Auxinfo(AuxinfoMessageType::R3Proof) => {
                self.handle_round_three_msg(rng, message, input)
            }
            MessageType::Auxinfo(_) => Err(InternalError::MessageMustBeBroadcasted),
            _ => Err(InternalError::MisroutedMessage),
        }
    }
}

impl InnerProtocolParticipant for AuxInfoParticipant {
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

impl Broadcast for AuxInfoParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl AuxInfoParticipant {
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling auxinfo ready message.");

        let (ready_outcome, is_ready) = self.process_ready_message::<storage::Ready>(message)?;

        if is_ready {
            let round_one_messages =
                run_only_once!(self.gen_round_one_msgs(rng, message), message.id())?;

            Ok(ready_outcome.with_messages(round_one_messages))
        } else {
            Ok(ready_outcome)
        }
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round one auxinfo messages.");

        let (auxinfo_private, auxinfo_public, auxinfo_witnesses) = new_auxinfo(self.id(), rng)?;
        self.local_storage
            .store::<storage::Private>(self.id, auxinfo_private);
        self.local_storage
            .store::<storage::Public>(self.id, auxinfo_public.clone());
        self.local_storage
            .store::<storage::Witnesses>(self.id, auxinfo_witnesses);

        let decom = AuxInfoDecommit::new(rng, &message.id(), &self.id, auxinfo_public)?;
        let com = decom.commit()?;

        self.local_storage
            .store::<storage::Commit>(self.id, com.clone());
        self.local_storage
            .store::<storage::Decommit>(self.id, decom);

        let messages = self.broadcast(
            rng,
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash),
            serialize!(&com)?,
            message.id(),
            BroadcastTag::AuxinfoR1CommitHash,
        )?;
        Ok(messages)
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: &BroadcastOutput,
        input: &(),
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round one auxinfo message.");

        if broadcast_message.tag != BroadcastTag::AuxinfoR1CommitHash {
            return Err(InternalError::IncorrectBroadcastMessageTag);
        }
        let message = &broadcast_message.msg;
        self.local_storage
            .store::<storage::Commit>(message.from(), AuxInfoCommit::from_message(message)?);

        // check if we've received all the commits.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(&self.other_participant_ids);

        if r1_done {
            // Generate messages for round two...
            let round_one_messages =
                run_only_once!(self.gen_round_two_msgs(rng, message), message.id())?;

            // ...and process any round two messages we may have received early.
            let round_two_outcomes = self
                .fetch_messages(
                    MessageType::Auxinfo(AuxinfoMessageType::R2Decommit),
                    message.id(),
                )?
                .iter()
                .map(|msg| self.handle_round_two_msg(rng, msg, input))
                .collect::<Result<Vec<_>>>()?;

            ProcessOutcome::collect_with_messages(round_two_outcomes, round_one_messages)
        } else {
            // Round 1 isn't done, so we have neither outputs nor new messages to send.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round two auxinfo messages.");

        // check that we've generated our public info before trying to retrieve it
        let public_keyshare_generated = self.local_storage.contains::<storage::Public>(self.id);
        let mut messages = vec![];
        if !public_keyshare_generated {
            let more_messages =
                run_only_once!(self.gen_round_one_msgs(rng, message), message.id())?;
            messages.extend_from_slice(&more_messages);
        }

        // retrieve your decom from storage
        let decom = self.local_storage.retrieve::<storage::Decommit>(self.id)?;
        let decom_bytes = serialize!(&decom)?;
        let more_messages: Vec<Message> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Auxinfo(AuxinfoMessageType::R2Decommit),
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

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &(),
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round two auxinfo message.");

        // We must receive all commitments in round 1 before we start processing
        // decommits in round 2.
        let r1_done = self.local_storage.contains_for_all_ids::<storage::Commit>(
            &[self.other_participant_ids.clone(), vec![self.id]].concat(),
        );
        if !r1_done {
            // store any early round2 messages
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        let decom = AuxInfoDecommit::from_message(message)?;
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(message.from())?;
        decom.verify(&message.id(), &message.from(), com)?;
        self.local_storage
            .store::<storage::Decommit>(message.from(), decom);

        // check if we've received all the decommits
        let r2_done = self
            .local_storage
            .contains_for_all_ids::<storage::Decommit>(&self.other_participant_ids);
        if r2_done {
            // Generate messages for round 3...
            let round_two_messages =
                run_only_once!(self.gen_round_three_msgs(rng, message), message.id())?;

            // ...and handle any messages that other participants have sent for round 3.
            let round_three_outcomes = self
                .fetch_messages(
                    MessageType::Auxinfo(AuxinfoMessageType::R3Proof),
                    message.id(),
                )?
                .iter()
                .map(|msg| self.handle_round_three_msg(rng, msg, input))
                .collect::<Result<Vec<_>>>()?;

            ProcessOutcome::collect_with_messages(round_three_outcomes, round_two_messages)
        } else {
            Ok(ProcessOutcome::Incomplete)
        }
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round three auxinfo messages.");

        let rids: Vec<[u8; 32]> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                let decom = self
                    .local_storage
                    .retrieve::<storage::Decommit>(other_participant_id)?;
                Ok(decom.rid())
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let my_decom = self.local_storage.retrieve::<storage::Decommit>(self.id)?;
        let my_public = self
            .local_storage
            .retrieve::<storage::Public>(self.id)?
            .clone();

        let mut global_rid = my_decom.rid();
        // xor all the rids together. In principle, many different options for combining
        // these should be okay
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.local_storage
            .store::<storage::GlobalRid>(self.id, global_rid);

        let witness = self.local_storage.retrieve::<storage::Witnesses>(self.id)?;

        let proof = AuxInfoProof::prove(
            rng,
            message.id(),
            global_rid,
            my_public.params(),
            &(&witness.p * &witness.q),
            &witness.p,
            &witness.q,
        )?;
        let proof_bytes = serialize!(&proof)?;

        let round_three_messages: Vec<Message> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Auxinfo(AuxinfoMessageType::R3Proof),
                    message.id(),
                    self.id,
                    other_participant_id,
                    &proof_bytes,
                )
            })
            .collect();
        Ok(round_three_messages)
    }

    /// Handle a message from round three. Since round 3 is the last round, this
    /// method never returns additional messages.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        _input: &(),
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round three auxinfo message.");

        // We can't handle this message unless we already calculated the global_rid
        if self
            .local_storage
            .retrieve::<storage::GlobalRid>(self.id)
            .is_err()
        {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        let global_rid = self.local_storage.retrieve::<storage::GlobalRid>(self.id)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;

        let auxinfo_pub = decom.clone().into_public();

        let proof = AuxInfoProof::from_message(message)?;
        proof.verify(
            message.id(),
            *global_rid,
            auxinfo_pub.params(),
            auxinfo_pub.pk().modulus(),
        )?;

        self.local_storage
            .store::<storage::Public>(message.from(), auxinfo_pub);

        // Check if we've stored all the public auxinfo_pubs
        let done = self
            .local_storage
            .contains_for_all_ids::<storage::Public>(&self.all_participants());

        // If so, we completed the protocol! Return the outputs.
        if done {
            let auxinfo_public = self
                .all_participants()
                .iter()
                .map(|pid| {
                    let value = self.local_storage.retrieve::<storage::Public>(*pid)?;
                    Ok(value.clone())
                })
                .collect::<Result<Vec<_>>>()?;
            let auxinfo_private = self.local_storage.retrieve::<storage::Private>(self.id)?;

            Ok(ProcessOutcome::Terminated((
                auxinfo_public,
                auxinfo_private.clone(),
            )))
        } else {
            // Otherwise, we'll have to wait for more round three messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }
}

#[cfg_attr(feature = "flame_it", flame("auxinfo"))]
#[instrument(skip_all, err(Debug))]
fn new_auxinfo<R: RngCore + CryptoRng>(
    participant: ParticipantIdentifier,
    rng: &mut R,
) -> Result<(AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses)> {
    debug!("Creating new auxinfo.");

    let (decryption_key, p, q) = DecryptionKey::new(rng)?;
    let params = VerifiedRingPedersen::extract(&decryption_key, rng)?;
    let encryption_key = decryption_key.encryption_key();

    Ok((
        decryption_key.into(),
        AuxInfoPublic::new(participant, encryption_key, params)?,
        AuxInfoWitnesses { p, q },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utils::testing::init_testing, Identifier};
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::HashMap;

    impl AuxInfoParticipant {
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
                .map(|&participant_id| -> AuxInfoParticipant {
                    // Filter out current participant id from list of other ids
                    let mut other_ids = vec![];
                    for &id in participant_ids.iter() {
                        if id != participant_id {
                            other_ids.push(id);
                        }
                    }
                    Self::new(participant_id, other_ids)
                })
                .collect::<Vec<AuxInfoParticipant>>();
            Ok(participants)
        }

        pub fn initialize_auxinfo_message(&self, auxinfo_identifier: Identifier) -> Message {
            Message::new(
                MessageType::Auxinfo(AuxinfoMessageType::Ready),
                auxinfo_identifier,
                self.id,
                self.id,
                &[],
            )
        }

        pub fn is_auxinfo_done(&self, _: Identifier) -> bool {
            self.local_storage
                .contains_for_all_ids::<storage::Public>(&self.all_participants())
                && self.local_storage.contains::<storage::Private>(self.id)
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

    fn is_auxinfo_done(
        quorum: &[AuxInfoParticipant],
        auxinfo_identifier: Identifier,
    ) -> Result<bool> {
        for participant in quorum {
            if !participant.is_auxinfo_done(auxinfo_identifier) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Pick a random participant and process one of the messages in their
    /// inbox.
    ///
    /// Returns None if there are no messages for the selected participant.
    #[allow(clippy::type_complexity)]
    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut Vec<AuxInfoParticipant>,
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
    ) -> Option<(usize, ProcessOutcome<(Vec<AuxInfoPublic>, AuxInfoPrivate)>)> {
        // Pick a random participant to process
        let index = rng.gen_range(0..quorum.len());
        let participant = quorum.get_mut(index).unwrap();

        let inbox = inboxes.get_mut(&participant.id).unwrap();
        if inbox.is_empty() {
            // No messages to process for this participant, so pick another participant
            return None;
        }
        // Pick a random message to process
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
    #[ignore = "slow"]
    // This test is cheap. Try a bunch of message permutations to decrease error
    // likelihood
    fn test_run_auxinfo_protocol_many_times() -> Result<()> {
        let _rng = init_testing();

        for _ in 0..20 {
            test_run_auxinfo_protocol()?;
        }
        Ok(())
    }
    #[test]
    fn test_run_auxinfo_protocol() -> Result<()> {
        let QUORUM_SIZE = 3;
        let mut rng = init_testing();
        let mut quorum = AuxInfoParticipant::new_quorum(QUORUM_SIZE, &mut rng)?;
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
            inbox.push(participant.initialize_auxinfo_message(keyshare_identifier));
        }
        while !is_auxinfo_done(&quorum, keyshare_identifier)? {
            // Try processing a message
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
        for party in &quorum {
            let pid = party.id;

            // Collect the AuxInfoPublic associated with pid from every output
            let mut publics_for_pid = vec![];
            for (publics, _) in &outputs {
                let public_key = publics
                    .iter()
                    .find(|public_key| *public_key.participant() == pid);
                assert!(public_key.is_some());
                // Check that it's valid while we're here.
                assert!(public_key.unwrap().verify().is_ok());
                publics_for_pid.push(public_key.unwrap());
            }

            // Make sure they're all equal
            assert!(publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]));
        }

        // Check that private outputs are consistent
        for ((publics, private), pid) in outputs.iter().zip(quorum.iter().map(|p| p.id())) {
            let public_key = publics
                .iter()
                .find(|public_key| *public_key.participant() == pid);
            assert!(public_key.is_some());
            assert_eq!(*public_key.unwrap().pk(), private.encryption_key());
        }

        Ok(())
    }
}
