// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::auxinfo::info::AuxInfoPrivate;
use crate::auxinfo::info::AuxInfoPublic;
use crate::errors::Result;
use crate::keygen::keyshare::KeySharePrivate;
use crate::keygen::keyshare::KeySharePublic;
use crate::messages::PresignMessageType;
use crate::messages::{Message, MessageType};
use crate::paillier::PaillierCiphertext;
use crate::parameters::ELL;
use crate::presign::record::{PresignRecord, RecordPair};
use crate::presign::round_one::{Private as RoundOnePrivate, Public as RoundOnePublic};
use crate::presign::round_three::RoundThreeInput;
use crate::presign::round_three::{Private as RoundThreePrivate, Public as RoundThreePublic};
use crate::presign::round_two::{Private as RoundTwoPrivate, Public as RoundTwoPublic};
use crate::protocol::ParticipantIdentifier;
use crate::storage::StorableType;
use crate::storage::Storage;
use crate::utils::{
    bn_to_scalar, get_other_participants_public_auxinfo, has_collected_all_of_others, k256_order,
    process_ready_message, random_bn_in_range, random_positive_bn,
};
use crate::zkp::piaffg::{PiAffgInput, PiAffgProof, PiAffgSecret};
use crate::zkp::pienc::PiEncProof;
use crate::zkp::pilog::{PiLogInput, PiLogProof, PiLogSecret};
use crate::zkp::Proof;
use crate::{CurvePoint, Identifier};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct PresignParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    storage: Storage,
    /// presign -> {keyshare, auxinfo} map
    presign_map: HashMap<Identifier, (Identifier, Identifier)>,
}

impl PresignParticipant {
    pub(crate) fn from_ids(
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
    ) -> Self {
        Self {
            id,
            other_participant_ids,
            storage: Storage::new(),
            presign_map: HashMap::new(),
        }
    }

    /// Processes the incoming message given the storage from the protocol participant
    /// (containing auxinfo and keygen artifacts). Optionally produces a [PresignRecord]
    /// once presigning is complete.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    pub(crate) fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        match message.message_type() {
            MessageType::Presign(PresignMessageType::Ready) => {
                let messages = self.handle_ready_msg(rng, message, main_storage)?;
                Ok((None, messages))
            }
            MessageType::Presign(PresignMessageType::RoundOne) => {
                let messages = self.handle_round_one_msg(rng, message, main_storage)?;
                Ok((None, messages))
            }
            MessageType::Presign(PresignMessageType::RoundTwo) => {
                let messages = self.handle_round_two_msg(rng, message, main_storage)?;
                Ok((None, messages))
            }
            MessageType::Presign(PresignMessageType::RoundThree) => {
                let (presign_record_option, messages) =
                    self.handle_round_three_msg(rng, message, main_storage)?;
                Ok((presign_record_option, messages))
            }
            _ => bail!("Attempting to process a non-presign message with a presign participant"),
        }
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<Vec<Message>> {
        let (mut messages, is_ready) = process_ready_message(
            self.id,
            &self.other_participant_ids,
            &mut self.storage,
            message,
            StorableType::KeygenReady,
        )?;

        if is_ready {
            let more_messages = self.gen_round_one_msgs(rng, message, main_storage)?;
            messages.extend_from_slice(&more_messages);
        }
        Ok(messages)
    }

    pub(crate) fn initialize_presign_message(
        &mut self,
        auxinfo_identifier: Identifier,
        keyshare_identifier: Identifier,
        identifier: Identifier,
    ) -> Message {
        // Set the presign map internally
        self.presign_map
            .insert(identifier, (auxinfo_identifier, keyshare_identifier));

        Message::new(
            MessageType::Presign(PresignMessageType::Ready),
            identifier,
            self.id,
            self.id,
            &[],
        )
    }

    /// Presign: Round One
    ///
    /// During round one, each participant produces and stores their own secret values, and then
    /// stores a round one secret, and publishes a unique public component to every other participant.
    ///
    /// This can only be run after all participants have finished with key generation.
    #[cfg_attr(feature = "flame_it", flame)]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<Vec<Message>> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.id())?;

        // Reconstruct keyshare and other participants' public keyshares from local storage
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
        let (private, r1_publics) = keyshare.round_one(rng, &other_public_auxinfo)?;

        // Store private r1 value locally
        self.storage.store(
            StorableType::RoundOnePrivate,
            message.id(),
            self.id,
            &serialize!(&private)?,
        )?;

        // Publish public r1 to all other participants on the channel
        let mut ret_messages = vec![];
        for (other_id, r1_public) in r1_publics {
            ret_messages.push(Message::new(
                MessageType::Presign(PresignMessageType::RoundOne),
                message.id(),
                self.id,
                other_id,
                &serialize!(&r1_public)?,
            ));
        }

        Ok(ret_messages)
    }

    /// Presign: Round Two
    ///
    /// During round two, each participant retrieves the public keyshares for each other participant from the
    /// key generation phase, the round 1 public values from each other participant, its own round 1 private
    /// value, and its own round one keyshare from key generation, and produces per-participant
    /// round 2 public and private values.
    ///
    /// This can be run as soon as each round one message to this participant has been published.
    /// These round two messages are returned in response to the sender, without having to
    /// rely on any other round one messages from other participants aside from the sender.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<Vec<Message>> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.id())?;

        // Reconstruct keyshare and other participants' public keyshares from local storage
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

        assert_eq!(message.to(), self.id);

        // Find the keyshare corresponding to the "from" participant
        let keyshare_from = other_public_keyshares.get(&message.from()).ok_or_else(|| {
            bail_context!("Could not find corresponding public keyshare for participant in round 2")
        })?;

        // Get this participant's round 1 private value
        let r1_priv = deserialize!(&self.storage.retrieve(
            StorableType::RoundOnePrivate,
            message.id(),
            message.to()
        )?)?;

        let r1_public = crate::round_one::Public::from_message(
            message,
            &keyshare.aux_info_public,
            keyshare_from,
        )?;

        // Store the round 1 public value as well
        self.storage.store(
            StorableType::RoundOnePublic,
            message.id(),
            message.from(),
            &serialize!(&r1_public)?,
        )?;

        let (r2_priv_ij, r2_pub_ij) = keyshare.round_two(rng, keyshare_from, &r1_priv, &r1_public);

        // Store the private value for this round 2 pair
        self.storage.store(
            StorableType::RoundTwoPrivate,
            message.id(),
            message.from(),
            &serialize!(&r2_priv_ij)?,
        )?;

        // Only a single message to be output here
        let message = Message::new(
            MessageType::Presign(PresignMessageType::RoundTwo),
            message.id(),
            self.id,
            message.from(), // This is a essentially response to that sender
            &serialize!(&r2_pub_ij)?,
        );
        Ok(vec![message])
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<Vec<Message>> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.id())?;

        // First, verify the bytes of the round two value, and then
        // store it locally. In order to v
        self.validate_and_store_round_two_public(
            main_storage,
            message,
            auxinfo_identifier,
            keyshare_identifier,
        )?;

        // Since we are in round 2, it should certainly be the case that all
        // public auxinfo for other participants have been stored, since
        // this was a requirement to proceed for round 1.
        assert!(has_collected_all_of_others(
            &self.other_participant_ids,
            main_storage,
            StorableType::AuxInfoPublic,
            auxinfo_identifier
        )?);

        // Check if storage has all of the other participants' round two values (both
        // private and public), and call do_round_three() if so
        match has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::RoundTwoPrivate,
            message.id(),
        )? && has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::RoundTwoPublic,
            message.id(),
        )? {
            true => Ok(self.gen_round_three_msgs(rng, message, main_storage)?),
            false => Ok(vec![]),
        }
    }

    /// Presign: Round Three
    ///
    /// During round three, to process all round 3 messages from a sender, the participant
    /// must first wait for round 2 to be completely finished for all participants.
    /// Then, the participant retrieves:
    /// - all participants' public keyshares,
    /// - its own round 1 private value,
    /// - all round 2 per-participant private values,
    /// - all round 2 per-participant public values,
    ///
    /// and produces a set of per-participant round 3 public values and one private value.
    ///
    /// Each participant is only going to run round three once.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<Vec<Message>> {
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
            StorableType::RoundOnePrivate,
            message.id(),
            self.id
        )?)?;

        let (r3_private, r3_publics_map) =
            keyshare.round_three(rng, &r1_priv, &round_three_hashmap)?;

        // Store round 3 private value
        self.storage.store(
            StorableType::RoundThreePrivate,
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

        Ok(ret_messages)
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn handle_round_three_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        main_storage: &Storage,
    ) -> Result<(Option<PresignRecord>, Vec<Message>)> {
        let (auxinfo_identifier, _) = self.get_associated_identifiers_for_presign(&message.id())?;

        // First, verify and store the round three value locally
        self.validate_and_store_round_three_public(main_storage, message, auxinfo_identifier)?;

        let mut presign_record = None;
        if has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::RoundThreePublic,
            message.id(),
        )? {
            presign_record = Some(self.do_presign_finish(message)?);
        }

        // No messages to return
        Ok((presign_record, vec![]))
    }
    /// Presign: Finish
    ///
    /// In this step, the participant simply collects all r3 public values and its r3
    /// private value, and assembles them into a PresignRecord.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn do_presign_finish(&mut self, message: &Message) -> Result<PresignRecord> {
        let r3_pubs = self.get_other_participants_round_three_publics(message.id())?;

        // Get this participant's round 3 private value
        let r3_private: RoundThreePrivate = deserialize!(&self.storage.retrieve(
            StorableType::RoundThreePrivate,
            message.id(),
            self.id
        )?)?;

        // Check consistency across all Gamma values
        for r3_pub in r3_pubs.iter() {
            if r3_pub.Gamma != r3_private.Gamma {
                return bail!("Inconsistency in presign finish -- Gamma mismatch");
            }
        }

        let presign_record: PresignRecord = RecordPair {
            private: r3_private,
            publics: r3_pubs,
        }
        .into();

        Ok(presign_record)
    }

    fn get_associated_identifiers_for_presign(
        &self,
        presign_identifier: &Identifier,
    ) -> Result<(Identifier, Identifier)> {
        let (id1, id2) = self.presign_map.get(presign_identifier).ok_or_else(
            || bail_context!("Could not find associated auxinfo and keyshare identifiers for this presign identifier")
        )?;

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
            StorableType::RoundOnePrivate,
            message.id(),
            message.to()
        )?)?;
        let sender_r1_public = deserialize!(&self.storage.retrieve(
            StorableType::RoundOnePublic,
            message.id(),
            message.from(),
        )?)?;

        let message_bytes = serialize!(&crate::round_two::Public::from_message(
            message,
            &receiver_auxinfo_public,
            &sender_auxinfo_public,
            &sender_keyshare_public,
            &receiver_r1_private,
            &sender_r1_public,
        )?)?;

        self.storage.store(
            StorableType::RoundTwoPublic,
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
        let sender_r1_public = deserialize!(&self.storage.retrieve(
            StorableType::RoundOnePublic,
            message.id(),
            message.from()
        )?)?;

        let message_bytes = serialize!(&crate::round_three::Public::from_message(
            message,
            &receiver_auxinfo_public,
            &sender_auxinfo_public,
            &sender_r1_public,
        )?)?;

        self.storage.store(
            StorableType::RoundThreePublic,
            message.id(),
            message.from(),
            &message_bytes,
        )?;

        Ok(())
    }

    /// Aggregate the other participants' values needed for round three from storage. This includes:
    /// - public keyshares
    /// - round two private values
    /// - round two public values
    ///
    /// This returns a HashMap with the key as the participant id and these values being mapped
    fn get_other_participants_round_three_values(
        &self,
        identifier: Identifier,
        auxinfo_identifier: Identifier,
        main_storage: &Storage,
    ) -> Result<HashMap<ParticipantIdentifier, RoundThreeInput>> {
        if !has_collected_all_of_others(
            &self.other_participant_ids,
            main_storage,
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
        )? || !has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::RoundTwoPrivate,
            identifier,
        )? || !has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::RoundTwoPublic,
            identifier,
        )? {
            return bail!("Not ready to get other participants round three values just yet!");
        }

        let mut hm = HashMap::new();
        for other_participant_id in self.other_participant_ids.clone() {
            let auxinfo_public = main_storage.retrieve(
                StorableType::AuxInfoPublic,
                auxinfo_identifier,
                other_participant_id,
            )?;
            let round_two_private = self.storage.retrieve(
                StorableType::RoundTwoPrivate,
                identifier,
                other_participant_id,
            )?;
            let round_two_public = self.storage.retrieve(
                StorableType::RoundTwoPublic,
                identifier,
                other_participant_id,
            )?;
            hm.insert(
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

    /// Aggregate the other participants' round three public values from storage. But don't remove them
    /// from storage.
    ///
    /// This returns a Vec with the values
    fn get_other_participants_round_three_publics(
        &self,
        identifier: Identifier,
    ) -> Result<Vec<crate::round_three::Public>> {
        if !has_collected_all_of_others(
            &self.other_participant_ids,
            &self.storage,
            StorableType::RoundThreePublic,
            identifier,
        )? {
            return bail!("Not ready to get other participants round three publics just yet!");
        }

        let mut ret_vec = vec![];
        for other_participant_id in self.other_participant_ids.clone() {
            let val = self.storage.retrieve(
                StorableType::RoundThreePublic,
                identifier,
                other_participant_id,
            )?;
            ret_vec.push(deserialize!(&val)?);
        }
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
    #[cfg_attr(feature = "flame_it", flame)]
    pub(crate) fn round_one<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        public_keys: &HashMap<ParticipantIdentifier, AuxInfoPublic>,
    ) -> Result<(
        RoundOnePrivate,
        HashMap<ParticipantIdentifier, RoundOnePublic>,
    )> {
        let order = k256_order();

        // Sample k <- F_q
        let k = random_positive_bn(rng, &order);
        // Sample gamma <- F_q
        let gamma = random_positive_bn(rng, &order);

        // Sample rho <- Z_N^* and set K = enc(k; rho)
        let (K, rho) = loop {
            let (K, rho) = self.aux_info_public.pk.encrypt(&k);
            if !BigNumber::is_zero(&rho) {
                break (K, rho);
            }
        };

        // Sample nu <- Z_N^* and set G = enc(gamma; nu)
        let (G, nu) = loop {
            let (G, nu) = self.aux_info_public.pk.encrypt(&gamma);

            if !BigNumber::is_zero(&nu) {
                break (G, nu);
            }
        };

        let mut ret_publics = HashMap::new();
        for (id, aux_info_public) in public_keys {
            // Compute psi_{j,i} for every participant j != i
            let proof = PiEncProof::prove(
                rng,
                &crate::zkp::pienc::PiEncInput::new(
                    &aux_info_public.params,
                    self.aux_info_public.pk.n(),
                    &PaillierCiphertext(K.clone()),
                ),
                &crate::zkp::pienc::PiEncSecret::new(&k, &rho),
            )?;
            let r1_public = RoundOnePublic {
                K: PaillierCiphertext(K.clone()),
                G: PaillierCiphertext(G.clone()),
                proof: proof.clone(),
            };
            ret_publics.insert(*id, r1_public);
        }

        let r1_private = RoundOnePrivate {
            k,
            rho,
            gamma,
            nu,
            G: PaillierCiphertext(G),
            K: PaillierCiphertext(K),
        };

        Ok((r1_private, ret_publics))
    }

    /// Needs to be run once per party j != i
    ///
    /// Constructs a D = gamma * K and D_hat = x * K, and Gamma = g * gamma.
    ///
    #[cfg_attr(feature = "flame_it", flame)]
    pub(crate) fn round_two<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        receiver_aux_info: &AuxInfoPublic,
        sender_r1_priv: &RoundOnePrivate,
        receiver_r1_pub: &RoundOnePublic,
    ) -> (RoundTwoPrivate, RoundTwoPublic) {
        // Picking betas as elements of [+- 2^384] here is like sampling them from the distribution
        // [1, 2^256], which is akin to 2^{ell + epsilon} where ell = epsilon = 384. Note that
        // we need q/2^epsilon to be negligible.
        let beta = random_bn_in_range(rng, ELL);
        let beta_hat = random_bn_in_range(rng, ELL);

        let (beta_ciphertext, s) = receiver_aux_info.pk.encrypt(&beta);
        let (beta_hat_ciphertext, s_hat) = receiver_aux_info.pk.encrypt(&beta_hat);

        let D = receiver_aux_info
            .pk
            .0
            .add(
                &receiver_aux_info
                    .pk
                    .0
                    .mul(&receiver_r1_pub.K.0, &sender_r1_priv.gamma)
                    .unwrap(),
                &beta_ciphertext,
            )
            .unwrap();

        let D_hat = receiver_aux_info
            .pk
            .0
            .add(
                &receiver_aux_info
                    .pk
                    .0
                    .mul(&receiver_r1_pub.K.0, &self.keyshare_private.x)
                    .unwrap(),
                &beta_hat_ciphertext,
            )
            .unwrap();

        let (F, r) = self.aux_info_public.pk.encrypt(&beta);
        let (F_hat, r_hat) = self.aux_info_public.pk.encrypt(&beta_hat);

        let g = CurvePoint::GENERATOR;
        let Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma).unwrap());

        // Generate three proofs

        let psi = PiAffgProof::prove(
            rng,
            &PiAffgInput::new(
                &receiver_aux_info.params,
                &g,
                receiver_aux_info.pk.n(),
                self.aux_info_public.pk.n(),
                &receiver_r1_pub.K.0,
                &D,
                &F,
                &Gamma,
            ),
            &PiAffgSecret::new(&sender_r1_priv.gamma, &beta, &s, &r),
        )
        .unwrap();

        let psi_hat = PiAffgProof::prove(
            rng,
            &PiAffgInput::new(
                &receiver_aux_info.params,
                &g,
                receiver_aux_info.pk.n(),
                self.aux_info_public.pk.n(),
                &receiver_r1_pub.K.0,
                &D_hat,
                &F_hat,
                &self.keyshare_public.X,
            ),
            &PiAffgSecret::new(&self.keyshare_private.x, &beta_hat, &s_hat, &r_hat),
        )
        .unwrap();

        let psi_prime = PiLogProof::prove(
            rng,
            &PiLogInput::new(
                &receiver_aux_info.params,
                &k256_order(),
                self.aux_info_public.pk.n(),
                &sender_r1_priv.G.0,
                &Gamma,
                &g,
            ),
            &PiLogSecret::new(&sender_r1_priv.gamma, &sender_r1_priv.nu),
        )
        .unwrap();

        (
            RoundTwoPrivate { beta, beta_hat },
            RoundTwoPublic {
                D: PaillierCiphertext(D),
                D_hat: PaillierCiphertext(D_hat),
                F: PaillierCiphertext(F),
                F_hat: PaillierCiphertext(F_hat),
                Gamma,
                psi,
                psi_hat,
                psi_prime,
            },
        )
    }

    /// From the perspective of party i
    /// r2_privs and r2_pubs don't include party i
    ///
    /// First computes alpha = dec(D), alpha_hat = dec(D_hat).
    /// Computes a delta = gamma * k
    #[cfg_attr(feature = "flame_it", flame)]
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
        let mut Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma).unwrap());

        for round_three_input in other_participant_inputs.values() {
            let r2_pub_j = round_three_input.r2_public.clone();
            let r2_priv_j = round_three_input.r2_private.clone();

            let alpha =
                BigNumber::from_slice(self.aux_info_private.sk.decrypt(&r2_pub_j.D.0).unwrap());
            let alpha_hat =
                BigNumber::from_slice(self.aux_info_private.sk.decrypt(&r2_pub_j.D_hat.0).unwrap());

            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);

            Gamma = CurvePoint(Gamma.0 + r2_pub_j.Gamma.0);
        }

        let Delta = CurvePoint(Gamma.0 * bn_to_scalar(&sender_r1_priv.k).unwrap());

        let delta_scalar = bn_to_scalar(&delta).unwrap();
        let chi_scalar = bn_to_scalar(&chi).unwrap();

        let mut ret_publics = HashMap::new();
        for (other_id, round_three_input) in other_participant_inputs {
            let psi_double_prime = PiLogProof::prove(
                rng,
                &PiLogInput::new(
                    &round_three_input.auxinfo_public.params,
                    &order,
                    self.aux_info_public.pk.n(),
                    &sender_r1_priv.K.0,
                    &Delta,
                    &Gamma,
                ),
                &PiLogSecret::new(&sender_r1_priv.k, &sender_r1_priv.rho),
            )
            .unwrap();
            let val = RoundThreePublic {
                delta: delta_scalar,
                Delta,
                psi_double_prime,
                Gamma,
            };
            ret_publics.insert(*other_id, val);
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
