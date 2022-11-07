// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::{
        auxinfo_commit::{AuxInfoCommit, AuxInfoDecommit},
        proof::AuxInfoProof,
    },
    broadcast::participant::{BroadcastOutput, BroadcastParticipant},
    errors::Result,
    messages::{AuxinfoMessageType, Message, MessageType},
    paillier::{PaillierDecryptionKey, PaillierEncryptionKey},
    parameters::PRIME_BITS,
    participant::{Broadcast, ProtocolParticipant},
    protocol::ParticipantIdentifier,
    run_only_once,
    storage::{StorableType, Storage},
    utils::process_ready_message,
    zkp::setup::ZkSetupParameters,
};
use libpaillier::{DecryptionKey, EncryptionKey};
use rand::{prelude::IteratorRandom, CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::info::{AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses};

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
    pub(crate) fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
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
            MessageType::Auxinfo(_) => bail!("This message must be broadcasted!"),
            _ => {
                bail!("Attempting to process a non-auxinfo message with a auxinfo participant")
            }
        }
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let (mut messages, is_ready) = process_ready_message(
            self.id,
            &self.other_participant_ids,
            &mut self.storage,
            message,
            StorableType::AuxInfoReady,
        )?;

        if is_ready {
            let more_messages =
                run_only_once!(self.gen_round_one_msgs(rng, message), message.id())?;
            messages.extend_from_slice(&more_messages);
        }
        Ok(messages)
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let (auxinfo_private, auxinfo_public, auxinfo_witnesses) = new_auxinfo(rng, PRIME_BITS)?;
        self.storage.store(
            StorableType::AuxInfoPrivate,
            message.id(),
            self.id,
            &serialize!(&auxinfo_private)?,
        )?;
        self.storage.store(
            StorableType::AuxInfoPublic,
            message.id(),
            self.id,
            &serialize!(&auxinfo_public)?,
        )?;
        self.storage.store(
            StorableType::AuxInfoWitnesses,
            message.id(),
            self.id,
            &serialize!(&auxinfo_witnesses)?,
        )?;

        let decom = AuxInfoDecommit::new(&message.id(), &self.id, &auxinfo_public);
        let com = decom.commit()?;
        let com_bytes = &serialize!(&com)?;

        self.storage.store(
            StorableType::AuxInfoCommit,
            message.id(),
            self.id,
            com_bytes,
        )?;
        self.storage.store(
            StorableType::AuxInfoDecommit,
            message.id(),
            self.id,
            &serialize!(&decom)?,
        )?;

        let messages = self.broadcast(
            rng,
            &MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash),
            com_bytes.clone(),
            message.id(),
            "AuxinfoR1CommitHash",
        )?;
        Ok(messages)
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: &BroadcastOutput,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        if broadcast_message.tag != "AuxinfoR1CommitHash" {
            return bail!("Incorrect tag for Auxinfo R1!");
        }
        let message = &broadcast_message.msg;
        let message_bytes = serialize!(&AuxInfoCommit::from_message(message)?)?;
        self.storage.store(
            StorableType::AuxInfoCommit,
            message.id(),
            message.from(),
            &message_bytes,
        )?;

        // check if we've received all the commits.
        let r1_done = self
            .storage
            .contains_for_all_ids(
                StorableType::AuxInfoCommit,
                message.id(),
                &self.other_participant_ids.clone(),
            )
            .is_ok();
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
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        // check that we've generated our public info before trying to retrieve it
        let fetch = vec![(StorableType::AuxInfoPublic, message.id(), self.id)];
        let public_keyshare_generated = self.storage.contains_batch(&fetch).is_ok();
        let mut messages = vec![];
        if !public_keyshare_generated {
            let more_messages =
                run_only_once!(self.gen_round_one_msgs(rng, message), message.id())?;
            messages.extend_from_slice(&more_messages);
        }

        // retreive your decom from storage
        let decom_bytes =
            self.storage
                .retrieve(StorableType::AuxInfoDecommit, message.id(), self.id)?;
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
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        // We must receive all commitments in round 1 before we start processing
        // decommits in round 2.
        let r1_done = self
            .storage
            .contains_for_all_ids(
                StorableType::AuxInfoCommit,
                message.id(),
                &[self.other_participant_ids.clone(), vec![self.id]].concat(),
            )
            .is_ok();
        if !r1_done {
            // store any early round2 messages
            self.stash_message(message)?;
            return Ok(vec![]);
        }
        let decom = AuxInfoDecommit::from_message(message)?;
        decom.pk.verify()?;

        let com_bytes =
            self.storage
                .retrieve(StorableType::AuxInfoCommit, message.id(), message.from())?;
        let com: AuxInfoCommit = deserialize!(&com_bytes)?;
        if !decom.verify(&message.id(), &message.from(), &com)? {
            return bail!("Decommitment Check Failed!");
        }
        self.storage.store(
            StorableType::AuxInfoDecommit,
            message.id(),
            message.from(),
            &serialize!(&decom)?,
        )?;

        // check if we've received all the decommits
        let r2_done = self
            .storage
            .contains_for_all_ids(
                StorableType::AuxInfoDecommit,
                message.id(),
                &self.other_participant_ids.clone(),
            )
            .is_ok();
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
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let rids: Vec<[u8; 32]> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                let decom: AuxInfoDecommit = deserialize!(&self
                    .storage
                    .retrieve(
                        StorableType::AuxInfoDecommit,
                        message.id(),
                        other_participant_id
                    )
                    .unwrap())
                .unwrap();
                decom.rid
            })
            .collect();
        let my_decom: AuxInfoDecommit = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoDecommit,
            message.id(),
            self.id
        )?)?;
        let my_public: AuxInfoPublic = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoPublic,
            message.id(),
            self.id
        )?)?;

        let mut global_rid = my_decom.rid;
        // xor all the rids together. In principle, many different options for combining
        // these should be okay
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.storage.store(
            StorableType::AuxInfoGlobalRid,
            message.id(),
            self.id,
            &serialize!(&global_rid)?,
        )?;

        let witness: AuxInfoWitnesses = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoWitnesses,
            message.id(),
            self.id
        )?)?;

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
    fn handle_round_three_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        // We can't handle this message unless we already calculated the global_rid
        if self
            .storage
            .retrieve(StorableType::AuxInfoGlobalRid, message.id(), self.id)
            .is_err()
        {
            self.stash_message(message)?;
            return Ok(vec![]);
        }

        let global_rid: [u8; 32] = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoGlobalRid,
            message.id(),
            self.id
        )?)?;
        let decom: AuxInfoDecommit = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoDecommit,
            message.id(),
            message.from()
        )?)?;

        let auxinfo_pub = decom.get_pk();

        let proof = AuxInfoProof::from_message(message)?;
        proof.verify(
            message.id(),
            global_rid,
            &auxinfo_pub.params,
            auxinfo_pub.pk.n(),
        )?;

        self.storage.store(
            StorableType::AuxInfoPublic,
            message.id(),
            message.from(),
            &serialize!(&auxinfo_pub)?,
        )?;

        //check if we've stored all the public auxinfo_pubs
        let keyshare_done = self
            .storage
            .contains_for_all_ids(
                StorableType::AuxInfoPublic,
                message.id(),
                &[self.other_participant_ids.clone(), vec![self.id]].concat(),
            )
            .is_ok();

        if keyshare_done {
            for oid in self.other_participant_ids.iter() {
                let keyshare_bytes =
                    self.storage
                        .retrieve(StorableType::AuxInfoPublic, message.id(), *oid)?;
                main_storage.store(
                    StorableType::AuxInfoPublic,
                    message.id(),
                    *oid,
                    &keyshare_bytes,
                )?;
            }
            let my_pk_bytes =
                self.storage
                    .retrieve(StorableType::AuxInfoPublic, message.id(), self.id)?;
            let my_sk_bytes =
                self.storage
                    .retrieve(StorableType::AuxInfoPrivate, message.id(), self.id)?;
            main_storage.store(
                StorableType::AuxInfoPublic,
                message.id(),
                self.id,
                &my_pk_bytes,
            )?;
            main_storage.store(
                StorableType::AuxInfoPrivate,
                message.id(),
                self.id,
                &my_sk_bytes,
            )?;
        }
        Ok(vec![])
    }
}

#[cfg_attr(feature = "flame_it", flame("auxinfo"))]
fn new_auxinfo<R: RngCore + CryptoRng>(
    rng: &mut R,
    _prime_bits: usize,
) -> Result<(AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses)> {
    // Pull in pre-generated safe primes from text file (not a safe operation!).
    // This is meant to save on the time needed to generate these primes, but
    // should not be done in a production environment!
    let safe_primes = crate::utils::get_safe_primes();
    let two_safe_primes = safe_primes.iter().choose_multiple(rng, 2);

    // FIXME: do proper safe prime generation
    //let p = BigNumber::safe_prime(prime_bits);
    //let q = BigNumber::safe_prime(prime_bits);

    let p = two_safe_primes[0].clone();
    let q = two_safe_primes[1].clone();

    let sk = PaillierDecryptionKey(
        DecryptionKey::with_safe_primes_unchecked(&p, &q)
            .ok_or_else(|| bail_context!("Could not generate decryption key"))?,
    );

    let pk = PaillierEncryptionKey(EncryptionKey::from(&sk.0));
    let params = ZkSetupParameters::gen_from_primes(rng, &(&p * &q), &p, &q)?;

    Ok((
        AuxInfoPrivate { sk },
        AuxInfoPublic { pk, params },
        AuxInfoWitnesses { p, q },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identifier;
    use rand::{
        rngs::{OsRng, StdRng},
        CryptoRng, Rng, RngCore, SeedableRng,
    };
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

        pub fn is_auxinfo_done(&self, auxinfo_identifier: Identifier) -> Result<()> {
            let mut fetch = vec![];
            for participant in self.other_participant_ids.clone() {
                fetch.push((StorableType::AuxInfoPublic, auxinfo_identifier, participant));
            }
            fetch.push((StorableType::AuxInfoPublic, auxinfo_identifier, self.id));
            fetch.push((StorableType::AuxInfoPrivate, auxinfo_identifier, self.id));

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
    ) -> Result<()> {
        for participant in quorum {
            if participant.is_auxinfo_done(auxinfo_identifier).is_err() {
                return bail!("Auxinfo not done");
            }
        }
        Ok(())
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
        println!(
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
        let mut osrng = OsRng;
        let seed = osrng.next_u64();
        // uncomment this line to test a specific seed
        // let seed: u64 = 11129769151581080362;
        let mut rng = StdRng::seed_from_u64(seed);
        println!("Initializing run with seed {}", seed);
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
        while is_auxinfo_done(&quorum, keyshare_identifier).is_err() {
            process_messages(&mut quorum, &mut inboxes, &mut rng, &mut main_storages)?;
        }

        // check that all players have a PublicKeyshare stored for every player and that
        // these values all match
        for player in quorum.iter() {
            let player_id = player.id;
            let mut stored_values = vec![];
            for main_storage in main_storages.iter() {
                let pk_bytes = main_storage.retrieve(
                    StorableType::AuxInfoPublic,
                    keyshare_identifier,
                    player_id,
                )?;
                stored_values.push(pk_bytes);
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
            let pk: AuxInfoPublic = deserialize!(&main_storage.retrieve(
                StorableType::AuxInfoPublic,
                keyshare_identifier,
                player_id
            )?)?;
            let sk: AuxInfoPrivate = deserialize!(&main_storage.retrieve(
                StorableType::AuxInfoPrivate,
                keyshare_identifier,
                player_id
            )?)?;
            let pk2 = PaillierEncryptionKey(EncryptionKey::from(&sk.sk.0));
            assert!(serialize!(&pk2) == serialize!(&pk.pk));
        }

        Ok(())
    }
}
