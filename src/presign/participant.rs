// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::info::{AuxInfoPrivate, AuxInfoPublic},
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{
        InternalError::{self, InternalInvariantFailed},
        Result,
    },
    keygen::keyshare::{KeySharePrivate, KeySharePublic},
    messages::{Message, MessageType, PresignMessageType},
    parameters::ELL_PRIME,
    participant::{Broadcast, ProtocolParticipant},
    presign::{
        record::{PresignRecord, RecordPair},
        round_one::{
            Private as RoundOnePrivate, Public as RoundOnePublic,
            PublicBroadcast as RoundOnePublicBroadcast,
        },
        round_three::{Private as RoundThreePrivate, Public as RoundThreePublic, RoundThreeInput},
        round_two::{Private as RoundTwoPrivate, Public as RoundTwoPublic},
    },
    protocol::ParticipantIdentifier,
    storage::{StorableType, Storage},
    utils::{
        bn_to_scalar, get_other_participants_public_auxinfo, has_collected_all_of_others,
        k256_order, process_ready_message, random_plusminus_by_size, random_positive_bn,
    },
    zkp::{
        piaffg::{PiAffgInput, PiAffgProof, PiAffgSecret},
        pienc::PiEncProof,
        pilog::{PiLogInput, PiLogProof, PiLogSecret},
        Proof,
    },
    CurvePoint, Identifier,
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct PresignParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    storage: Storage,
    /// presign -> {keyshare, auxinfo} map
    presign_map: HashMap<Identifier, (Identifier, Identifier)>,
    /// Broadcast subprotocol handler
    broadcast_participant: BroadcastParticipant,
}

impl ProtocolParticipant for PresignParticipant {
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

impl Broadcast for PresignParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl PresignParticipant {
    pub(crate) fn from_ids(
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
    ) -> Self {
        Self {
            id,
            other_participant_ids: other_participant_ids.clone(),
            storage: Storage::new(),
            presign_map: HashMap::new(),
            broadcast_participant: BroadcastParticipant::from_ids(id, other_participant_ids),
        }
    }

    /// Processes the incoming message given the storage from the protocol
    /// participant (containing auxinfo and keygen artifacts). Optionally
    /// produces a [PresignRecord] once presigning is complete.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    pub(crate) fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        match message.message_type() {
            MessageType::Presign(PresignMessageType::Ready) => {
                Ok(self.handle_ready_msg(rng, message, main_storage)?)
            }
            MessageType::Presign(PresignMessageType::RoundOneBroadcast) => {
                match self.handle_broadcast(rng, message)? {
                    (Some(bmsg), mut messages) => {
                        let (pr, more_messages) =
                            self.handle_round_one_broadcast_msg(rng, &bmsg, main_storage)?;
                        messages.extend_from_slice(&more_messages);
                        Ok((pr, messages))
                    }
                    (None, messages) => Ok((None, messages)),
                }
            }
            MessageType::Presign(PresignMessageType::RoundOne) => {
                Ok(self.handle_round_one_msg(rng, message, main_storage)?)
            }
            MessageType::Presign(PresignMessageType::RoundTwo) => {
                Ok(self.handle_round_two_msg(rng, message, main_storage)?)
            }
            MessageType::Presign(PresignMessageType::RoundThree) => {
                Ok(self.handle_round_three_msg(rng, message, main_storage)?)
            }
            _ => Err(InternalError::MisroutedMessage),
        }
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        let (mut messages, is_ready) = process_ready_message(
            self.id,
            &self.other_participant_ids,
            &mut self.storage,
            message,
            StorableType::PresignReady,
        )?;

        if is_ready {
            let (pr, more_messages) = self.gen_round_one_msgs(rng, message, main_storage)?;
            messages.extend_from_slice(&more_messages);
            Ok((pr, messages))
        } else {
            Ok((None, messages))
        }
    }

    pub(crate) fn initialize_presign_message(
        &mut self,
        auxinfo_identifier: Identifier,
        keyshare_identifier: Identifier,
        identifier: Identifier,
    ) -> Result<Message> {
        if self.presign_map.contains_key(&identifier) {
            return Err(InternalError::IdentifierInUse);
        }
        // Set the presign map internally
        let _ = self
            .presign_map
            .insert(identifier, (auxinfo_identifier, keyshare_identifier));

        let message = Message::new(
            MessageType::Presign(PresignMessageType::Ready),
            identifier,
            self.id,
            self.id,
            &[],
        );
        Ok(message)
    }

    /// Presign: Round One
    ///
    /// During round one, each participant produces and stores their own secret
    /// values, and then stores a round one secret, and publishes a unique
    /// public component to every other participant.
    ///
    /// This can only be run after all participants have finished with key
    /// generation.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.id())?;

        // Reconstruct keyshare and other participants' public keyshares from local
        // storage
        let keyshare = get_keyshare(
            self.id,
            auxinfo_identifier,
            keyshare_identifier,
            main_storage,
        )?;
        let other_public_auxinfo = get_other_participants_public_auxinfo(
            &self.other_participant_ids,
            main_storage,
            auxinfo_identifier,
        )?;

        // Run Round One
        let (private, r1_publics, r1_public_broadcast) =
            keyshare.round_one(rng, &other_public_auxinfo)?;

        // Store private round one value locally
        self.storage.store(
            StorableType::PresignRoundOnePrivate,
            message.id(),
            self.id,
            &serialize!(&private)?,
        )?;

        // Publish public round one value to all other participants on the channel
        let mut out_messages = vec![];
        for (other_id, r1_public) in r1_publics {
            out_messages.push(Message::new(
                MessageType::Presign(PresignMessageType::RoundOne),
                message.id(),
                self.id,
                other_id,
                &serialize!(&r1_public)?,
            ));
        }

        let mut broadcast_messages = self.broadcast(
            rng,
            &MessageType::Presign(PresignMessageType::RoundOneBroadcast),
            serialize!(&r1_public_broadcast)?,
            message.id(),
            BroadcastTag::PresignR1Ciphertexts,
        )?;
        out_messages.append(&mut broadcast_messages);

        // Additionally, handle any round 1 messages which may have been received too
        // early
        let retrieved_messages = self.fetch_messages(
            MessageType::Presign(PresignMessageType::RoundOne),
            message.id(),
        )?;
        let mut presign_record = None;
        for msg in retrieved_messages {
            let (pr, mut r2_msg) = self.handle_round_one_msg(rng, &msg, main_storage)?;
            out_messages.append(&mut r2_msg);

            // Check that pr is only ever assigned to at most once.
            match (pr, &presign_record) {
                // Found some _pr_ and presign_record has never been assigned to. Assign to it.
                (Some(pr), None) => presign_record = Some(pr),
                // We have already assigned to presign_record once! This should not happen again!
                // TODO: Add logging message here once we have logging set up.
                (Some(_), Some(_)) => return Err(InternalInvariantFailed),
                (None, _) => { /* Nothing to do */ }
            }
        }

        Ok((presign_record, out_messages))
    }

    fn handle_round_one_broadcast_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: &BroadcastOutput,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        if broadcast_message.tag != BroadcastTag::PresignR1Ciphertexts {
            return Err(InternalError::IncorrectBroadcastMessageTag);
        }
        let message = &broadcast_message.msg;
        self.storage.store(
            StorableType::PresignRoundOnePublicBroadcast,
            message.id(),
            message.from(),
            &message.unverified_bytes,
        )?;

        // Check to see if we have already stored the other part of round one. If so,
        // retrieve and process it
        let retrieved_messages = self.fetch_messages_by_sender(
            MessageType::Presign(PresignMessageType::RoundOne),
            message.id(),
            message.from(),
        )?;
        let non_broadcasted_portion = match retrieved_messages.get(0) {
            Some(message) => message,
            None => return Ok((None, vec![])),
        };
        self.handle_round_one_msg(rng, non_broadcasted_portion, main_storage)
    }

    /// Processes a single request from round one to create public keyshares for
    /// that participant, to be sent in round two.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        // Check if we have both have received the broadcasted ciphertexts that we need
        // in order to respond and have started round one
        let search_keys = [
            (
                StorableType::PresignRoundOnePublicBroadcast,
                message.id(),
                message.from(),
            ),
            (
                StorableType::PresignRoundOnePrivate,
                message.id(),
                message.to(),
            ),
        ];
        if !self.storage.contains_batch(&search_keys)? {
            self.stash_message(message)?;
            return Ok((None, vec![]));
        }
        self.gen_round_two_msg(rng, message, main_storage)
    }

    /// Presign: Round Two
    ///
    /// During round two, each participant retrieves the public keyshares for
    /// each other participant from the key generation phase, the round 1
    /// public values from each other participant, its own round 1 private
    /// value, and its own round one keyshare from key generation, and produces
    /// per-participant round 2 public and private values.
    ///
    /// This can be run as soon as each round one message to this participant
    /// has been published. These round two messages are returned in
    /// response to the sender, without having to rely on any other round
    /// one messages from other participants aside from the sender.
    fn gen_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.id())?;

        // Reconstruct keyshare and other participants' public keyshares from local
        // storage
        let keyshare = get_keyshare(
            self.id,
            auxinfo_identifier,
            keyshare_identifier,
            main_storage,
        )?;
        let other_public_keyshares = get_other_participants_public_auxinfo(
            &self.other_participant_ids,
            main_storage,
            auxinfo_identifier,
        )?;

        // Find the keyshare corresponding to the "from" participant
        let keyshare_from = other_public_keyshares
            .get(&message.from())
            .ok_or(InternalInvariantFailed)?;

        // Get this participant's round 1 private value
        let r1_priv: RoundOnePrivate = deserialize!(&self.storage.retrieve(
            StorableType::PresignRoundOnePrivate,
            message.id(),
            message.to()
        )?)?;

        // Get the round one message broadcasted by this sender
        let r1_public_broadcast: RoundOnePublicBroadcast = deserialize!(&self.storage.retrieve(
            StorableType::PresignRoundOnePublicBroadcast,
            message.id(),
            message.from()
        )?)?;

        let r1_public = crate::round_one::Public::from_message(
            message,
            &keyshare.aux_info_public,
            keyshare_from,
            &r1_public_broadcast,
        )?;

        // Store the round 1 public value
        self.storage.store(
            StorableType::PresignRoundOnePublic,
            message.id(),
            message.from(),
            &serialize!(&r1_public)?,
        )?;

        let (r2_priv_ij, r2_pub_ij) =
            keyshare.round_two(rng, keyshare_from, &r1_priv, &r1_public_broadcast)?;

        // Store the private value for this round 2 pair
        self.storage.store(
            StorableType::PresignRoundTwoPrivate,
            message.id(),
            message.from(),
            &serialize!(&r2_priv_ij)?,
        )?;

        let out_message = Message::new(
            MessageType::Presign(PresignMessageType::RoundTwo),
            message.id(),
            self.id,
            message.from(), // This is a essentially response to that sender
            &serialize!(&r2_pub_ij)?,
        );

        let mut messages = vec![out_message];
        // Check if there's a round 2 message that this now allows us to process
        let retrieved_messages = self.fetch_messages_by_sender(
            MessageType::Presign(PresignMessageType::RoundTwo),
            message.id(),
            message.from(),
        )?;
        let r2_message = match retrieved_messages.get(0) {
            Some(message) => message,
            None => return Ok((None, messages)),
        };
        let (presign_record_option, mut additional_messages) =
            self.handle_round_two_msg(rng, r2_message, main_storage)?;
        messages.append(&mut additional_messages);
        Ok((presign_record_option, messages))
    }

    /// Process a single request from round two
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        // First, check that the sender's Round One messages have been processed
        let search_key = [(
            StorableType::PresignRoundOnePublic,
            message.id(),
            message.from(),
        )];
        if !self.storage.contains_batch(&search_key)? {
            self.stash_message(message)?;
            return Ok((None, vec![]));
        }

        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.id())?;

        // Verify the bytes of the round two value, and store it locally.
        self.validate_and_store_round_two_public(
            main_storage,
            message,
            auxinfo_identifier,
            keyshare_identifier,
        )?;

        // Since we are in round 2, it should certainly be the case that all
        // public auxinfo for other participants have been stored, since
        // this was a requirement to proceed for round 1.
        if !has_collected_all_of_others(
            &self.other_participant_ids,
            main_storage,
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
        )? {
            return Err(InternalError::StorageItemNotFound);
        }

        // Check if storage has all of the other participants' round 2 values (both
        // private and public), and start generating the messages for round 3 if so
        let all_privates_received = has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::PresignRoundTwoPrivate,
            message.id(),
        )?;
        let all_publics_received = has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::PresignRoundTwoPublic,
            message.id(),
        )?;
        if all_privates_received && all_publics_received {
            Ok(self.gen_round_three_msgs(rng, message, main_storage)?)
        } else {
            Ok((None, vec![]))
        }
    }

    /// Presign: Round Three
    ///
    /// During round three, to process all round 3 messages from a sender, the
    /// participant must first wait for round 2 to be completely finished
    /// for all participants. Then, the participant retrieves:
    /// - all participants' public keyshares,
    /// - its own round 1 private value,
    /// - all round 2 per-participant private values,
    /// - all round 2 per-participant public values,
    ///
    /// and produces a set of per-participant round 3 public values and one
    /// private value.
    ///
    /// Each participant is only going to run round three once.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.id())?;

        // Reconstruct keyshare from local storage
        let keyshare = get_keyshare(
            self.id,
            auxinfo_identifier,
            keyshare_identifier,
            main_storage,
        )?;

        let round_three_hashmap = self.get_other_participants_round_three_values(
            message.id(),
            auxinfo_identifier,
            main_storage,
        )?;

        // Get this participant's round 1 private value
        let r1_priv = deserialize!(&self.storage.retrieve(
            StorableType::PresignRoundOnePrivate,
            message.id(),
            self.id
        )?)?;

        let (r3_private, r3_publics_map) =
            keyshare.round_three(rng, &r1_priv, &round_three_hashmap)?;

        // Store round 3 private value
        self.storage.store(
            StorableType::PresignRoundThreePrivate,
            message.id(),
            self.id,
            &serialize!(&r3_private)?,
        )?;

        // Publish public r3 values to all other participants on the channel
        let mut ret_messages = vec![];
        for (id, r3_public) in r3_publics_map {
            ret_messages.push(Message::new(
                MessageType::Presign(PresignMessageType::RoundThree),
                message.id(),
                self.id,
                id,
                &serialize!(&r3_public)?,
            ));
        }

        // Additionally, handle any round 3 messages which may have been received too
        // early
        let mut presign_record = None;
        let retrieved_messages = self.fetch_messages(
            MessageType::Presign(PresignMessageType::RoundThree),
            message.id(),
        )?;
        for msg in retrieved_messages {
            let (pr, _) = self.handle_round_three_msg(rng, &msg, main_storage)?;
            // Check that pr is only ever assigned to at most once.
            match (pr, &presign_record) {
                // Found some _pr_ and presign_record has never been assigned to. Assign to it.
                (Some(pr), None) => presign_record = Some(pr),
                // We have already assigned to presign_record once! This should not happen again!
                // TODO: Add logging message here once we have logging set up.
                (Some(_), Some(_)) => return Err(InternalInvariantFailed),
                (None, _) => { /* Nothing to do */ }
            }
        }

        Ok((presign_record, ret_messages))
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn handle_round_three_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        // If we have not yet started round three, stash the message for later
        let r3_started = self
            .storage
            .retrieve(
                StorableType::PresignRoundThreePrivate,
                message.id(),
                self.id,
            )
            .is_ok();
        if !r3_started {
            self.stash_message(message)?;
            return Ok((None, vec![]));
        }

        let (auxinfo_identifier, _) = self.get_associated_identifiers_for_presign(&message.id())?;

        // First, verify and store the round three value locally
        self.validate_and_store_round_three_public(main_storage, message, auxinfo_identifier)?;

        let mut presign_record_option = None;
        if has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::PresignRoundThreePublic,
            message.id(),
        )? {
            presign_record_option = Some(self.do_presign_finish(message)?);
        }

        // No messages to return
        Ok((presign_record_option, vec![]))
    }

    /// Presign: Finish
    ///
    /// In this step, the participant simply collects all r3 public values and
    /// its r3 private value, and assembles them into a PresignRecord.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn do_presign_finish(&mut self, message: &Message) -> Result<PresignRecord> {
        let r3_pubs = self.get_other_participants_round_three_publics(message.id())?;

        // Get this participant's round 3 private value
        let r3_private: RoundThreePrivate = deserialize!(&self.storage.retrieve(
            StorableType::PresignRoundThreePrivate,
            message.id(),
            self.id
        )?)?;

        // Check consistency across all Gamma values
        for r3_pub in r3_pubs.iter() {
            if r3_pub.Gamma != r3_private.Gamma {
                return Err(InternalInvariantFailed);
            }
        }

        let presign_record: PresignRecord = RecordPair {
            private: r3_private,
            publics: r3_pubs,
        }
        .try_into()?;

        Ok(presign_record)
    }

    fn get_associated_identifiers_for_presign(
        &self,
        presign_identifier: &Identifier,
    ) -> Result<(Identifier, Identifier)> {
        let (id1, id2) = self
            .presign_map
            .get(presign_identifier)
            .ok_or(InternalInvariantFailed)?;

        Ok((*id1, *id2))
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn validate_and_store_round_two_public(
        &mut self,
        main_storage: &Storage,
        message: &Message,
        auxinfo_identifier: Identifier,
        keyshare_identifier: Identifier,
    ) -> Result<()> {
        let receiver_auxinfo_public = deserialize!(&main_storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            message.to()
        )?)?;
        let sender_auxinfo_public = deserialize!(&main_storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            message.from()
        )?)?;
        let sender_keyshare_public = deserialize!(&main_storage.retrieve(
            StorableType::PublicKeyshare,
            keyshare_identifier,
            message.from()
        )?)?;
        let receiver_r1_private = deserialize!(&self.storage.retrieve(
            StorableType::PresignRoundOnePrivate,
            message.id(),
            message.to()
        )?)?;
        let sender_r1_public_broadcast = deserialize!(&self.storage.retrieve(
            StorableType::PresignRoundOnePublicBroadcast,
            message.id(),
            message.from(),
        )?)?;

        let message_bytes = serialize!(&crate::round_two::Public::from_message(
            message,
            &receiver_auxinfo_public,
            &sender_auxinfo_public,
            &sender_keyshare_public,
            &receiver_r1_private,
            &sender_r1_public_broadcast,
        )?)?;

        self.storage.store(
            StorableType::PresignRoundTwoPublic,
            message.id(),
            message.from(),
            &message_bytes,
        )?;

        Ok(())
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn validate_and_store_round_three_public(
        &mut self,
        main_storage: &Storage,
        message: &Message,
        auxinfo_identifier: Identifier,
    ) -> Result<()> {
        let receiver_auxinfo_public = deserialize!(&main_storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            message.to()
        )?)?;
        let sender_auxinfo_public = deserialize!(&main_storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            message.from()
        )?)?;
        let sender_r1_public_broadcast = deserialize!(&self.storage.retrieve(
            StorableType::PresignRoundOnePublicBroadcast,
            message.id(),
            message.from()
        )?)?;

        let message_bytes = serialize!(&crate::round_three::Public::from_message(
            message,
            &receiver_auxinfo_public,
            &sender_auxinfo_public,
            &sender_r1_public_broadcast,
        )?)?;

        self.storage.store(
            StorableType::PresignRoundThreePublic,
            message.id(),
            message.from(),
            &message_bytes,
        )?;

        Ok(())
    }

    /// Aggregate the other participants' values needed for round three from
    /// storage. This includes:
    /// - public keyshares
    /// - round two private values
    /// - round two public values
    ///
    /// This returns a HashMap with the key as the participant id and these
    /// values being mapped
    fn get_other_participants_round_three_values(
        &self,
        identifier: Identifier,
        auxinfo_identifier: Identifier,
        main_storage: &Storage,
    ) -> Result<HashMap<ParticipantIdentifier, RoundThreeInput>> {
        // begin by checking Storage contents to ensure we're ready for round three
        if !has_collected_all_of_others(
            &self.other_participant_ids,
            main_storage,
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
        )? || !has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::PresignRoundTwoPrivate,
            identifier,
        )? || !has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::PresignRoundTwoPublic,
            identifier,
        )? {
            return Err(InternalError::StorageItemNotFound);
        }

        let mut hm = HashMap::new();
        for other_participant_id in self.other_participant_ids.clone() {
            let auxinfo_public = main_storage.retrieve(
                StorableType::AuxInfoPublic,
                auxinfo_identifier,
                other_participant_id,
            )?;
            let round_two_private = self.storage.retrieve(
                StorableType::PresignRoundTwoPrivate,
                identifier,
                other_participant_id,
            )?;
            let round_two_public = self.storage.retrieve(
                StorableType::PresignRoundTwoPublic,
                identifier,
                other_participant_id,
            )?;
            let _ = hm.insert(
                other_participant_id,
                RoundThreeInput {
                    auxinfo_public: deserialize!(&auxinfo_public)?,
                    r2_private: deserialize!(&round_two_private)?,
                    r2_public: deserialize!(&round_two_public)?,
                },
            );
        }
        Ok(hm)
    }

    /// Aggregate the other participants' round three public values from
    /// storage. But don't remove them from storage.
    ///
    /// This returns a Vec with the values
    fn get_other_participants_round_three_publics(
        &self,
        identifier: Identifier,
    ) -> Result<Vec<crate::round_three::Public>> {
        if !has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::PresignRoundThreePublic,
            identifier,
        )? {
            return Err(InternalError::StorageItemNotFound);
        }
        let ret_vec = self
            .other_participant_ids
            .iter()
            .map(|other_participant_id| {
                let r3pub = deserialize!(&self.storage.retrieve(
                    StorableType::PresignRoundThreePublic,
                    identifier,
                    *other_participant_id,
                )?)?;
                Ok(r3pub)
            })
            .collect::<Result<Vec<crate::round_three::Public>>>()?;
        Ok(ret_vec)
    }
}

pub(crate) fn get_keyshare(
    self_id: ParticipantIdentifier,
    auxinfo_identifier: Identifier,
    keyshare_identifier: Identifier,
    storage: &Storage,
) -> Result<PresignKeyShareAndInfo> {
    // Reconstruct keyshare from local storage
    let keyshare_and_info = PresignKeyShareAndInfo {
        aux_info_private: deserialize!(&storage.retrieve(
            StorableType::AuxInfoPrivate,
            auxinfo_identifier,
            self_id
        )?)?,
        aux_info_public: deserialize!(&storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            self_id
        )?)?,
        keyshare_private: deserialize!(&storage.retrieve(
            StorableType::PrivateKeyshare,
            keyshare_identifier,
            self_id
        )?)?,
        keyshare_public: deserialize!(&storage.retrieve(
            StorableType::PublicKeyshare,
            keyshare_identifier,
            self_id
        )?)?,
    };
    Ok(keyshare_and_info)
}

/////////////////
// Round Logic //
/////////////////

/// Convenience struct used to bundle together the parameters for
/// the current participant
pub(crate) struct PresignKeyShareAndInfo {
    pub(crate) keyshare_private: KeySharePrivate,
    pub(crate) keyshare_public: KeySharePublic,
    pub(crate) aux_info_private: AuxInfoPrivate,
    pub(crate) aux_info_public: AuxInfoPublic,
}

impl PresignKeyShareAndInfo {
    /// Corresponds to pre-signing round 1 for party i
    ///
    /// Produces local shares k and gamma, along with their encrypted
    /// components K = enc(k) and G = enc(gamma).
    ///
    /// The public_keys parameter corresponds to a KeygenPublic for
    /// each of the other parties.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    pub(crate) fn round_one<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        public_keys: &HashMap<ParticipantIdentifier, AuxInfoPublic>,
    ) -> Result<(
        RoundOnePrivate,
        HashMap<ParticipantIdentifier, RoundOnePublic>,
        RoundOnePublicBroadcast,
    )> {
        let order = k256_order();

        // Sample k <- F_q
        let k = random_positive_bn(rng, &order);
        // Sample gamma <- F_q
        let gamma = random_positive_bn(rng, &order);

        // Sample rho <- Z_N^* and set K = enc(k; rho)
        let (K, rho) = self.aux_info_public.pk.encrypt(rng, &k)?;
        // Sample nu <- Z_N^* and set G = enc(gamma; nu)
        let (G, nu) = self.aux_info_public.pk.encrypt(rng, &gamma)?;

        let mut r1_publics = HashMap::new();
        for (id, aux_info_public) in public_keys {
            // Compute psi_{j,i} for every participant j != i
            let proof = PiEncProof::prove(
                rng,
                &crate::zkp::pienc::PiEncInput::new(
                    aux_info_public.params.clone(),
                    self.aux_info_public.pk.clone(),
                    K.clone(),
                ),
                &crate::zkp::pienc::PiEncSecret::new(k.clone(), rho.clone()),
            )?;
            let r1_public = RoundOnePublic { proof };
            let _ = r1_publics.insert(*id, r1_public);
        }

        let r1_public_broadcast = RoundOnePublicBroadcast {
            K: K.clone(),
            G: G.clone(),
        };

        let r1_private = RoundOnePrivate {
            k,
            rho,
            gamma,
            nu,
            G,
            K,
        };

        Ok((r1_private, r1_publics, r1_public_broadcast))
    }

    /// Needs to be run once per party j != i
    ///
    /// Constructs a D = gamma * K and D_hat = x * K, and Gamma = g * gamma.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    pub(crate) fn round_two<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        receiver_aux_info: &AuxInfoPublic,
        sender_r1_priv: &RoundOnePrivate,
        receiver_r1_pub_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<(RoundTwoPrivate, RoundTwoPublic)> {
        let beta = random_plusminus_by_size(rng, ELL_PRIME);
        let beta_hat = random_plusminus_by_size(rng, ELL_PRIME);

        // Note: The implementation specifies that we should encrypt the negative betas
        // here (see Figure 7, Round 2, #2, first two bullets) and add them when
        // we decrypt (see Figure 7, Round 3, #2, first bullet -- computation of
        // delta and chi) However, it doesn't explain how this squares with the
        // `PiAffgProof`, which requires the plaintext of `beta_ciphertext`
        // (used to compute `D`) to match the plaintext of `F` (below). If we
        // make this negative, PiAffg fails to verify because the signs don't match.
        //
        // A quick look at the proof suggests that the important thing is that the
        // values are equal. The betas are components of additive shares of
        // secret values, so it shouldn't matter where the negation happens
        // (Round 2 vs Round 3).
        let (beta_ciphertext, s) = receiver_aux_info.pk.encrypt(rng, &beta)?;
        let (beta_hat_ciphertext, s_hat) = receiver_aux_info.pk.encrypt(rng, &beta_hat)?;

        let D = receiver_aux_info.pk.multiply_and_add(
            &sender_r1_priv.gamma,
            &receiver_r1_pub_broadcast.K,
            &beta_ciphertext,
        )?;
        let D_hat = receiver_aux_info.pk.multiply_and_add(
            &self.keyshare_private.x,
            &receiver_r1_pub_broadcast.K,
            &beta_hat_ciphertext,
        )?;
        let (F, r) = self.aux_info_public.pk.encrypt(rng, &beta)?;
        let (F_hat, r_hat) = self.aux_info_public.pk.encrypt(rng, &beta_hat)?;

        let g = CurvePoint::GENERATOR;
        let Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma)?);

        // Generate three proofs

        let psi = PiAffgProof::prove(
            rng,
            &PiAffgInput::new(
                &receiver_aux_info.params,
                &g,
                &receiver_aux_info.pk,
                &self.aux_info_public.pk,
                &receiver_r1_pub_broadcast.K,
                &D,
                &F,
                &Gamma,
            ),
            &PiAffgSecret::new(&sender_r1_priv.gamma, &beta, &s, &r),
        )?;

        let psi_hat = PiAffgProof::prove(
            rng,
            &PiAffgInput::new(
                &receiver_aux_info.params,
                &g,
                &receiver_aux_info.pk,
                &self.aux_info_public.pk,
                &receiver_r1_pub_broadcast.K,
                &D_hat,
                &F_hat,
                &self.keyshare_public.X,
            ),
            &PiAffgSecret::new(&self.keyshare_private.x, &beta_hat, &s_hat, &r_hat),
        )?;

        let psi_prime = PiLogProof::prove(
            rng,
            &PiLogInput::new(
                &receiver_aux_info.params,
                &k256_order(),
                &self.aux_info_public.pk,
                &sender_r1_priv.G,
                &Gamma,
                &g,
            ),
            &PiLogSecret::new(&sender_r1_priv.gamma, &sender_r1_priv.nu),
        )?;

        Ok((
            RoundTwoPrivate { beta, beta_hat },
            RoundTwoPublic {
                D,
                D_hat,
                F,
                F_hat,
                Gamma,
                psi,
                psi_hat,
                psi_prime,
            },
        ))
    }

    /// From the perspective of party i
    /// r2_privs and r2_pubs don't include party i
    ///
    /// First computes alpha = dec(D), alpha_hat = dec(D_hat).
    /// Computes a delta = gamma * k
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    pub(crate) fn round_three<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        sender_r1_priv: &RoundOnePrivate,
        other_participant_inputs: &HashMap<ParticipantIdentifier, RoundThreeInput>,
    ) -> Result<(
        RoundThreePrivate,
        HashMap<ParticipantIdentifier, RoundThreePublic>,
    )> {
        let order = k256_order();
        let mut delta: BigNumber = sender_r1_priv.gamma.modmul(&sender_r1_priv.k, &order);
        let mut chi: BigNumber = self.keyshare_private.x.modmul(&sender_r1_priv.k, &order);

        let g = CurvePoint::GENERATOR;
        let mut Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma)?);

        for round_three_input in other_participant_inputs.values() {
            let r2_pub_j = round_three_input.r2_public.clone();
            let r2_priv_j = round_three_input.r2_private.clone();

            let alpha = self.aux_info_private.sk.decrypt(&r2_pub_j.D)?;
            let alpha_hat = self.aux_info_private.sk.decrypt(&r2_pub_j.D_hat)?;

            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);
            Gamma = CurvePoint(Gamma.0 + r2_pub_j.Gamma.0);
        }

        let Delta = CurvePoint(Gamma.0 * bn_to_scalar(&sender_r1_priv.k)?);

        let delta_scalar = bn_to_scalar(&delta)?;
        let chi_scalar = bn_to_scalar(&chi)?;

        let mut ret_publics = HashMap::new();
        for (other_id, round_three_input) in other_participant_inputs {
            let psi_double_prime = PiLogProof::prove(
                rng,
                &PiLogInput::new(
                    &round_three_input.auxinfo_public.params,
                    &order,
                    &self.aux_info_public.pk,
                    &sender_r1_priv.K,
                    &Delta,
                    &Gamma,
                ),
                &PiLogSecret::new(&sender_r1_priv.k, &sender_r1_priv.rho),
            )?;
            let val = RoundThreePublic {
                delta: delta_scalar,
                Delta,
                psi_double_prime,
                Gamma,
            };
            let _ = ret_publics.insert(*other_id, val);
        }

        let private = RoundThreePrivate {
            k: sender_r1_priv.k.clone(),
            chi: chi_scalar,
            Gamma,
            // These last two fields can be public, but for convenience
            // are stored in this party's private component
            delta: delta_scalar,
            Delta,
        };

        Ok((private, ret_publics))
    }
}
