// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use super::info::{AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses};
use crate::{
    auxinfo::{
        auxinfo_commit::{AuxInfoCommit, AuxInfoDecommit},
        proof::AuxInfoProof,
    },
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{InternalError, Result},
    messages::{AuxinfoMessageType, Message, MessageType},
    paillier::DecryptionKey,
    participant::{Broadcast, ProtocolParticipant},
    protocol::ParticipantIdentifier,
    ring_pedersen::VerifiedRingPedersen,
    run_only_once,
    storage::{Storable, Storage},
    utils::process_ready_message,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};

/// Storage identifiers for the auxinfo protocol.
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) enum StorageType {
    Ready,
    Private,
    Public,
    Commit,
    Decommit,
    GlobalRid,
    Witnesses,
}

impl Storable for StorageType {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct AuxInfoParticipant {
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

impl ProtocolParticipant for AuxInfoParticipant {
    fn storage(&self) -> &Storage {
        &self.storage
    }

    fn storage_mut(&mut self) -> &mut Storage {
        &mut self.storage
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }
}

impl Broadcast for AuxInfoParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl AuxInfoParticipant {
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

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        info!("Processing auxinfo message.");

        match message.message_type() {
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash) => {
                let (broadcast_option, mut messages) = self.handle_broadcast(rng, message)?;
                if let Some(bmsg) = broadcast_option {
                    let more_messages = self.handle_round_one_msg(rng, &bmsg, main_storage)?;
                    messages.extend_from_slice(&more_messages);
                };
                Ok(messages)
            }
            MessageType::Auxinfo(AuxinfoMessageType::Ready) => {
                let messages = self.handle_ready_msg(rng, message)?;
                Ok(messages)
            }
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit) => {
                let messages = self.handle_round_two_msg(rng, message, main_storage)?;
                Ok(messages)
            }
            MessageType::Auxinfo(AuxinfoMessageType::R3Proof) => {
                let messages = self.handle_round_three_msg(rng, message, main_storage)?;
                Ok(messages)
            }
            MessageType::Auxinfo(_) => Err(InternalError::MessageMustBeBroadcasted),
            _ => Err(InternalError::MisroutedMessage),
        }
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Handling auxinfo ready message.");

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

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        info!("Generating round one auxinfo messages.");

        let (auxinfo_private, auxinfo_public, auxinfo_witnesses) = new_auxinfo(rng)?;
        self.storage.store(
            StorageType::Private,
            message.id(),
            self.id,
            &auxinfo_private,
        )?;
        self.storage
            .store(StorageType::Public, message.id(), self.id, &auxinfo_public)?;
        self.storage.store(
            StorageType::Witnesses,
            message.id(),
            self.id,
            &auxinfo_witnesses,
        )?;

        let decom = AuxInfoDecommit::new(rng, &message.id(), &self.id, &auxinfo_public);
        let com = decom.commit()?;
        let com_bytes = &serialize!(&com)?;

        self.storage
            .store(StorageType::Commit, message.id(), self.id, &com)?;
        self.storage
            .store(StorageType::Decommit, message.id(), self.id, &decom)?;

        let messages = self.broadcast(
            rng,
            &MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash),
            com_bytes.clone(),
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
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        info!("Handling round one auxinfo message.");

        if broadcast_message.tag != BroadcastTag::AuxinfoR1CommitHash {
            return Err(InternalError::IncorrectBroadcastMessageTag);
        }
        let message = &broadcast_message.msg;
        self.storage.store(
            StorageType::Commit,
            message.id(),
            message.from(),
            &AuxInfoCommit::from_message(message)?,
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
                    MessageType::Auxinfo(AuxinfoMessageType::R2Decommit),
                    message.id(),
                )?
                .iter()
            {
                messages.extend_from_slice(&self.handle_round_two_msg(rng, msg, main_storage)?);
            }
        }
        Ok(messages)
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
        let fetch = vec![(StorageType::Public, message.id(), self.id)];
        let public_keyshare_generated = self.storage.contains_batch(&fetch)?;
        let mut messages = vec![];
        if !public_keyshare_generated {
            let more_messages =
                run_only_once!(self.gen_round_one_msgs(rng, message), message.id())?;
            messages.extend_from_slice(&more_messages);
        }

        // retrieve your decom from storage
        let decom: AuxInfoDecommit =
            self.storage
                .retrieve(StorageType::Decommit, message.id(), self.id)?;
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
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        info!("Handling round two auxinfo message.");

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
        let decom = AuxInfoDecommit::from_message(message)?;
        decom.pk.verify()?;

        let com: AuxInfoCommit =
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
                    MessageType::Auxinfo(AuxinfoMessageType::R3Proof),
                    message.id(),
                )?
                .iter()
            {
                messages.extend_from_slice(&self.handle_round_three_msg(rng, msg, main_storage)?);
            }
        }
        Ok(messages)
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
                let decom: AuxInfoDecommit = self.storage.retrieve(
                    StorageType::Decommit,
                    message.id(),
                    other_participant_id,
                )?;
                Ok(decom.rid)
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let my_decom: AuxInfoDecommit =
            self.storage
                .retrieve(StorageType::Decommit, message.id(), self.id)?;
        let my_public: AuxInfoPublic =
            self.storage
                .retrieve(StorageType::Public, message.id(), self.id)?;

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

        let witness: AuxInfoWitnesses =
            self.storage
                .retrieve(StorageType::Witnesses, message.id(), self.id)?;

        let proof = AuxInfoProof::prove(
            rng,
            message.id(),
            global_rid,
            &my_public.params,
            &(&witness.p * &witness.q),
            &witness.p,
            &witness.q,
        )?;
        let proof_bytes = serialize!(&proof)?;

        let more_messages: Vec<Message> = self
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
        Ok(more_messages)
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        info!("Handling round three auxinfo message.");

        // We can't handle this message unless we already calculated the global_rid
        if self
            .storage
            .retrieve::<StorageType, [u8; 32]>(StorageType::GlobalRid, message.id(), self.id)
            .is_err()
        {
            self.stash_message(message)?;
            return Ok(vec![]);
        }

        let global_rid: [u8; 32] =
            self.storage
                .retrieve(StorageType::GlobalRid, message.id(), self.id)?;
        let decom: AuxInfoDecommit =
            self.storage
                .retrieve(StorageType::Decommit, message.id(), message.from())?;

        let auxinfo_pub = decom.get_pk();

        let proof = AuxInfoProof::from_message(message)?;
        proof.verify(
            message.id(),
            global_rid,
            &auxinfo_pub.params,
            auxinfo_pub.pk.modulus(),
        )?;

        self.storage.store(
            StorageType::Public,
            message.id(),
            message.from(),
            &auxinfo_pub,
        )?;

        //check if we've stored all the public auxinfo_pubs
        let keyshare_done = self.storage.contains_for_all_ids(
            StorageType::Public,
            message.id(),
            &[self.other_participant_ids.clone(), vec![self.id]].concat(),
        )?;

        if keyshare_done {
            for oid in self.other_participant_ids.iter() {
                self.storage.transfer::<StorageType, AuxInfoPublic>(
                    main_storage,
                    StorageType::Public,
                    message.id(),
                    *oid,
                )?;
            }
            self.storage.transfer::<StorageType, AuxInfoPublic>(
                main_storage,
                StorageType::Public,
                message.id(),
                self.id,
            )?;
            self.storage.transfer::<StorageType, AuxInfoPrivate>(
                main_storage,
                StorageType::Private,
                message.id(),
                self.id,
            )?;
        }
        Ok(vec![])
    }
}

#[cfg_attr(feature = "flame_it", flame("auxinfo"))]
#[instrument(skip_all, err(Debug))]
fn new_auxinfo<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses)> {
    debug!("Creating new auxinfo.");

    let (decryption_key, p, q) = DecryptionKey::new(rng)?;
    let params = VerifiedRingPedersen::extract(&decryption_key, rng)?;
    let encryption_key = decryption_key.encryption_key();

    Ok((
        AuxInfoPrivate { sk: decryption_key },
        AuxInfoPublic {
            pk: encryption_key,
            params,
        },
        AuxInfoWitnesses { p, q },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identifier;
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::HashMap;
    use test_log::test;

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
                    Self::from_ids(participant_id, other_ids)
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

        pub fn is_auxinfo_done(&self, auxinfo_identifier: Identifier) -> Result<bool> {
            let mut fetch = vec![];
            for participant in self.other_participant_ids.clone() {
                fetch.push((StorageType::Public, auxinfo_identifier, participant));
            }
            fetch.push((StorageType::Public, auxinfo_identifier, self.id));
            fetch.push((StorageType::Private, auxinfo_identifier, self.id));

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

    fn is_auxinfo_done(
        quorum: &[AuxInfoParticipant],
        auxinfo_identifier: Identifier,
    ) -> Result<bool> {
        for participant in quorum {
            if !participant.is_auxinfo_done(auxinfo_identifier)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut Vec<AuxInfoParticipant>,
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
        let messages = participant.process_message(rng, &message, main_storage)?;
        deliver_all(&messages, inboxes)?;

        Ok(())
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    #[ignore = "slow"]
    // This test is cheap. Try a bunch of message permutations to decrease error
    // likelihood
    fn test_run_auxinfo_protocol_many_times() -> Result<()> {
        for _ in 0..20 {
            test_run_auxinfo_protocol()?;
        }
        Ok(())
    }
    #[test]
    fn test_run_auxinfo_protocol() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
        let mut quorum = AuxInfoParticipant::new_quorum(3, &mut rng)?;
        let mut inboxes = HashMap::new();
        let mut main_storages: Vec<Storage> = vec![];
        for participant in &quorum {
            let _ = inboxes.insert(participant.id, vec![]);
            main_storages.append(&mut vec![Storage::new()]);
        }

        let keyshare_identifier = Identifier::random(&mut rng);

        for participant in &quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_auxinfo_message(keyshare_identifier));
        }
        while !is_auxinfo_done(&quorum, keyshare_identifier)? {
            process_messages(&mut quorum, &mut inboxes, &mut rng, &mut main_storages)?;
        }

        // check that all players have a PublicKeyshare stored for every player and that
        // these values all match
        for player in quorum.iter() {
            let player_id = player.id;
            let mut stored_values = vec![];
            for main_storage in main_storages.iter() {
                let pk: AuxInfoPublic =
                    main_storage.retrieve(StorageType::Public, keyshare_identifier, player_id)?;
                stored_values.push(serialize!(&pk)?);
            }
            let base = stored_values.pop();
            while !stored_values.is_empty() {
                assert!(base == stored_values.pop());
            }
        }

        // check that each player's own AuxInfoPublic corresponds to their
        // AuxInfoPrivate
        for index in 0..quorum.len() {
            let player = quorum.get(index).unwrap();
            let player_id = player.id;
            let main_storage = main_storages.get(index).unwrap();
            let pk: AuxInfoPublic =
                main_storage.retrieve(StorageType::Public, keyshare_identifier, player_id)?;
            let sk: AuxInfoPrivate =
                main_storage.retrieve(StorageType::Private, keyshare_identifier, player_id)?;
            let pk2 = sk.sk.encryption_key();
            assert!(serialize!(&pk2) == serialize!(&pk.pk));
        }

        Ok(())
    }
}
