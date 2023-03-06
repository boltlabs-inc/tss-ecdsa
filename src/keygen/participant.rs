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
    messages::{KeygenMessageType, Message, MessageType},
    participant::{Broadcast, ProcessOutcome, ProtocolParticipant},
    protocol::ParticipantIdentifier,
    run_only_once,
    storage::{PersistentStorageType, Storable, Storage},
    utils::{k256_order, process_ready_message},
    zkp::pisch::{PiSchInput, PiSchPrecommit, PiSchProof, PiSchSecret},
    CurvePoint,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

// Storage identifiers for the keygen protocol.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "KeyGen")]
enum StorageType {
    Ready,
    Commit,
    Decommit,
    SchnorrPrecom,
    GlobalRid,
}

impl Storable for StorageType {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct KeygenParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    storage: Storage,
    /// Broadcast subprotocol handler
    broadcast_participant: BroadcastParticipant,
}

impl ProtocolParticipant for KeygenParticipant {
    // Currently, KeyGen puts output directly into persistent storage instead of
    // returning it to the calling Participant.
    // TODO #194: Update this type to actually define the output.
    type Output = ();

    fn storage(&self) -> &Storage {
        &self.storage
    }

    fn storage_mut(&mut self) -> &mut Storage {
        &mut self.storage
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing keygen message.");

        let messages = match message.message_type() {
            MessageType::Keygen(KeygenMessageType::R1CommitHash) => {
                let (broadcast_option, mut messages) = self.handle_broadcast(rng, message)?;
                if let Some(bmsg) = broadcast_option {
                    let more_messages = self.handle_round_one_msg(rng, &bmsg, main_storage)?;
                    messages.extend_from_slice(&more_messages);
                };
                messages
            }
            MessageType::Keygen(KeygenMessageType::Ready) => self.handle_ready_msg(rng, message)?,
            MessageType::Keygen(KeygenMessageType::R2Decommit) => {
                self.handle_round_two_msg(rng, message, main_storage)?
            }
            MessageType::Keygen(KeygenMessageType::R3Proof) => {
                self.handle_round_three_msg(rng, message, main_storage)?
            }
            MessageType::Keygen(_) => Err(InternalError::MessageMustBeBroadcasted)?,
            _ => Err(InternalError::MisroutedMessage)?,
        };

        // TODO #194: This is wrong, the protocol will finish at some point.
        Ok(ProcessOutcome::Processed(messages))
    }
}

impl Broadcast for KeygenParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl KeygenParticipant {
    pub(crate) fn from_ids(
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
    ) -> Self {
        Self {
            id,
            other_participant_ids: other_participant_ids.clone(),
            storage: Storage::new(),
            broadcast_participant: BroadcastParticipant::from_ids(id, other_participant_ids),
        }
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Handling ready keygen message.");

        let (mut messages, is_ready) = process_ready_message(
            self.id,
            &self.other_participant_ids,
            &mut self.storage,
            message,
            StorageType::Ready,
        )?;

        if is_ready {
            let more_messages =
                run_only_once!(self.gen_round_one_msgs(rng, message), message.id())?;
            messages.extend_from_slice(&more_messages);
        }
        Ok(messages)
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round one keygen messages.");

        let (keyshare_private, keyshare_public) = new_keyshare(rng)?;
        self.storage.store(
            PersistentStorageType::PrivateKeyshare,
            message.id(),
            self.id,
            &keyshare_private,
        )?;
        self.storage.store(
            PersistentStorageType::PublicKeyshare,
            message.id(),
            self.id,
            &keyshare_public,
        )?;

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

        self.storage
            .store(StorageType::Commit, message.id(), self.id, &com)?;
        self.storage
            .store(StorageType::Decommit, message.id(), self.id, &decom)?;
        self.storage.store(
            StorageType::SchnorrPrecom,
            message.id(),
            self.id,
            &sch_precom,
        )?;

        let messages = self.broadcast(
            rng,
            &MessageType::Keygen(KeygenMessageType::R1CommitHash),
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
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        info!("Handling round one keygen message.");

        if broadcast_message.tag != BroadcastTag::KeyGenR1CommitHash {
            return Err(InternalError::IncorrectBroadcastMessageTag);
        }
        let message = &broadcast_message.msg;
        self.storage.store(
            StorageType::Commit,
            message.id(),
            message.from(),
            &KeygenCommit::from_message(message)?,
        )?;

        // check if we've received all the commits.
        let r1_done = self.storage.contains_for_all_ids(
            StorageType::Commit,
            message.id(),
            &self.other_participant_ids.clone(),
        )?;
        let mut messages = vec![];

        if r1_done {
            let more_messages =
                run_only_once!(self.gen_round_two_msgs(rng, message), message.id())?;
            messages.extend_from_slice(&more_messages);
            // process any round 2 messages we may have received early
            for msg in self
                .fetch_messages(
                    MessageType::Keygen(KeygenMessageType::R2Decommit),
                    message.id(),
                )?
                .iter()
            {
                messages.extend_from_slice(&self.handle_round_two_msg(rng, msg, main_storage)?);
            }
        }
        Ok(messages)
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round two keygen messages.");

        // check that we've generated our keyshare before trying to retrieve it
        let fetch = vec![(PersistentStorageType::PublicKeyshare, message.id(), self.id)];
        let public_keyshare_generated = self.storage.contains_batch(&fetch)?;
        let mut messages = vec![];
        if !public_keyshare_generated {
            let more_messages =
                run_only_once!(self.gen_round_one_msgs(rng, message), message.id())?;
            messages.extend_from_slice(&more_messages);
        }

        // retreive your decom from storage
        let decom: KeygenDecommit =
            self.storage
                .retrieve(StorageType::Decommit, message.id(), self.id)?;
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
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        info!("Handling round two keygen message.");
        // We must receive all commitments in round 1 before we start processing
        // decommits in round 2.
        let r1_done = self.storage.contains_for_all_ids(
            StorageType::Commit,
            message.id(),
            &[self.other_participant_ids.clone(), vec![self.id]].concat(),
        )?;
        if !r1_done {
            // store any early round2 messages
            self.stash_message(message)?;
            return Ok(vec![]);
        }
        let decom = KeygenDecommit::from_message(message)?;
        let com: KeygenCommit =
            self.storage
                .retrieve(StorageType::Commit, message.id(), message.from())?;
        decom.verify(&message.id(), &message.from(), &com)?;
        self.storage
            .store(StorageType::Decommit, message.id(), message.from(), &decom)?;

        // check if we've received all the decommits
        let r2_done = self.storage.contains_for_all_ids(
            StorageType::Decommit,
            message.id(),
            &self.other_participant_ids.clone(),
        )?;
        let mut messages = vec![];

        if r2_done {
            let more_messages =
                run_only_once!(self.gen_round_three_msgs(rng, message), message.id())?;
            messages.extend_from_slice(&more_messages);
            for msg in self
                .fetch_messages(
                    MessageType::Keygen(KeygenMessageType::R3Proof),
                    message.id(),
                )?
                .iter()
            {
                messages.extend_from_slice(&self.handle_round_three_msg(rng, msg, main_storage)?);
            }
        }
        Ok(messages)
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
                let decom: KeygenDecommit = self.storage.retrieve(
                    StorageType::Decommit,
                    message.id(),
                    other_participant_id,
                )?;
                Ok(decom.rid)
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let my_decom: KeygenDecommit =
            self.storage
                .retrieve(StorageType::Decommit, message.id(), self.id)?;
        let mut global_rid = my_decom.rid;
        // xor all the rids together. In principle, many different options for combining
        // these should be okay
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.storage
            .store(StorageType::GlobalRid, message.id(), self.id, &global_rid)?;

        let mut transcript = Transcript::new(b"keygen schnorr");
        transcript.append_message(b"rid", &serialize!(&global_rid)?);
        let precom: PiSchPrecommit =
            self.storage
                .retrieve(StorageType::SchnorrPrecom, message.id(), self.id)?;

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);
        let my_pk: KeySharePublic =
            self.storage
                .retrieve(PersistentStorageType::PublicKeyshare, message.id(), self.id)?;
        let input = PiSchInput::new(&g, &q, &my_pk.X);

        let my_sk: KeySharePrivate = self.storage.retrieve(
            PersistentStorageType::PrivateKeyshare,
            message.id(),
            self.id,
        )?;

        let proof = PiSchProof::prove_from_precommit(
            &precom,
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
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        info!("Handling round three keygen message.");

        // We can't handle this message unless we already calculated the global_rid
        if self
            .storage
            .retrieve::<StorageType, [u8; 32]>(StorageType::GlobalRid, message.id(), self.id)
            .is_err()
        {
            self.stash_message(message)?;
            return Ok(vec![]);
        }
        let proof = PiSchProof::from_message(message)?;
        let global_rid: [u8; 32] =
            self.storage
                .retrieve(StorageType::GlobalRid, message.id(), self.id)?;
        let decom: KeygenDecommit =
            self.storage
                .retrieve(StorageType::Decommit, message.id(), message.from())?;

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);
        let input = PiSchInput::new(&g, &q, &decom.pk.X);

        let mut transcript = Transcript::new(b"keygen schnorr");
        transcript.append_message(b"rid", &serialize!(&global_rid)?);

        proof.verify_with_transcript(&input, &transcript)?;
        let keyshare = decom.get_keyshare();
        self.storage.store(
            PersistentStorageType::PublicKeyshare,
            message.id(),
            message.from(),
            &keyshare,
        )?;

        //check if we've stored all the public keyshares
        let keyshare_done = self.storage.contains_for_all_ids(
            PersistentStorageType::PublicKeyshare,
            message.id(),
            &[self.other_participant_ids.clone(), vec![self.id]].concat(),
        )?;

        if keyshare_done {
            for oid in self.other_participant_ids.iter() {
                self.storage.transfer::<_, KeySharePublic>(
                    main_storage,
                    PersistentStorageType::PublicKeyshare,
                    message.id(),
                    *oid,
                )?;
            }
            self.storage.transfer::<_, KeySharePublic>(
                main_storage,
                PersistentStorageType::PublicKeyshare,
                message.id(),
                self.id,
            )?;
            self.storage.transfer::<_, KeySharePrivate>(
                main_storage,
                PersistentStorageType::PrivateKeyshare,
                message.id(),
                self.id,
            )?;
        }
        Ok(vec![])
    }
}

/// Generates a new [KeySharePrivate] and [KeySharePublic]
fn new_keyshare<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(KeySharePrivate, KeySharePublic)> {
    let order = k256_order();
    let x = BigNumber::from_rng(&order, rng);
    let g = CurvePoint::GENERATOR;
    let X = CurvePoint(g.0 * crate::utils::bn_to_scalar(&x)?);

    Ok((KeySharePrivate { x }, KeySharePublic { X }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identifier;
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::HashMap;
    use test_log::test;
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
                    Self::from_ids(participant_id, other_ids)
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
        pub fn is_keygen_done(&self, keygen_identifier: Identifier) -> Result<bool> {
            let mut fetch = vec![];
            for participant in self.other_participant_ids.clone() {
                fetch.push((
                    PersistentStorageType::PublicKeyshare,
                    keygen_identifier,
                    participant,
                ));
            }
            fetch.push((
                PersistentStorageType::PublicKeyshare,
                keygen_identifier,
                self.id,
            ));
            fetch.push((
                PersistentStorageType::PrivateKeyshare,
                keygen_identifier,
                self.id,
            ));

            self.storage.contains_batch(&fetch)
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

    fn is_keygen_done(quorum: &[KeygenParticipant], keygen_identifier: Identifier) -> Result<bool> {
        for participant in quorum {
            if !participant.is_keygen_done(keygen_identifier)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut Vec<KeygenParticipant>,
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
        main_storages: &mut [Storage],
    ) -> Result<()> {
        // Pick a random participant to process
        let index = rng.gen_range(0..quorum.len());
        let participant = quorum.get_mut(index).unwrap();

        let inbox = inboxes.get_mut(&participant.id).unwrap();
        if inbox.is_empty() {
            // No messages to process for this participant, so pick another participant
            return Ok(());
        }
        let main_storage = main_storages.get_mut(index).unwrap();

        let index = rng.gen_range(0..inbox.len());
        let message = inbox.remove(index);
        debug!(
            "processing participant: {}, with message type: {:?} from {}",
            &participant.id,
            &message.message_type(),
            &message.from(),
        );
        let outcome = participant.process_message(rng, &message, main_storage)?;
        deliver_all(&outcome.into_messages(), inboxes)?;

        Ok(())
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    #[ignore = "slow"]
    // This test is cheap. Try a bunch of message permutations to decrease error
    // likelihood
    fn test_run_keygen_protocol_many_times() -> Result<()> {
        for _ in 0..20 {
            test_run_keygen_protocol()?;
        }
        Ok(())
    }
    #[test]
    fn test_run_keygen_protocol() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
        let mut quorum = KeygenParticipant::new_quorum(3, &mut rng)?;
        let mut inboxes = HashMap::new();
        let mut main_storages: Vec<Storage> = vec![];
        for participant in &quorum {
            let _ = inboxes.insert(participant.id, vec![]);
            main_storages.append(&mut vec![Storage::new()]);
        }

        let keyshare_identifier = Identifier::random(&mut rng);

        for participant in &quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_keygen_message(keyshare_identifier));
        }
        while !is_keygen_done(&quorum, keyshare_identifier)? {
            process_messages(&mut quorum, &mut inboxes, &mut rng, &mut main_storages)?;
        }

        // check that all players have a PublicKeyshare stored for every player and that
        // these values all match
        for player in quorum.iter() {
            let player_id = player.id;
            let mut stored_values = vec![];
            for main_storage in main_storages.iter() {
                let pk: KeySharePublic = main_storage.retrieve(
                    PersistentStorageType::PublicKeyshare,
                    keyshare_identifier,
                    player_id,
                )?;
                stored_values.push(serialize!(&pk)?);
            }
            let base = stored_values.pop();
            while !stored_values.is_empty() {
                assert!(base == stored_values.pop());
            }
        }

        // check that each player's own PublicKeyshare corresponds to their
        // PrivateKeyshare
        for index in 0..quorum.len() {
            let player = quorum.get(index).unwrap();
            let player_id = player.id;
            let main_storage = main_storages.get(index).unwrap();
            let pk: KeySharePublic = main_storage.retrieve(
                PersistentStorageType::PublicKeyshare,
                keyshare_identifier,
                player_id,
            )?;
            let sk: KeySharePrivate = main_storage.retrieve(
                PersistentStorageType::PrivateKeyshare,
                keyshare_identifier,
                player_id,
            )?;
            let g = CurvePoint::GENERATOR;
            let X = CurvePoint(g.0 * crate::utils::bn_to_scalar(&sk.x)?);
            assert!(X == pk.X);
        }

        Ok(())
    }
}
