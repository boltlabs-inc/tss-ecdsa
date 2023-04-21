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
    errors::{InternalError, Result},
    keygen::keyshare::{KeySharePrivate, KeySharePublic},
    local_storage::LocalStorage,
    messages::{Message, MessageType, PresignMessageType},
    parameters::ELL_PRIME,
    participant::{Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    presign::{
        record::{PresignRecord, RecordPair},
        round_one::{
            Private as RoundOnePrivate, Public as RoundOnePublic,
            PublicBroadcast as RoundOnePublicBroadcast,
        },
        round_three::{Private as RoundThreePrivate, Public as RoundThreePublic, RoundThreeInput},
        round_two::{Private as RoundTwoPrivate, Public as RoundTwoPublic},
    },
    protocol::{ParticipantIdentifier, ProtocolType},
    utils::{bn_to_scalar, k256_order, random_plusminus_by_size, random_positive_bn},
    zkp::{
        piaffg::{PiAffgInput, PiAffgProof, PiAffgSecret},
        pienc::PiEncProof,
        pilog::{CommonInput, PiLogProof, ProverSecret},
        Proof, ProofContext,
    },
    CurvePoint,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use tracing::{error, info, instrument};

// Local storage data types.
mod storage {
    use crate::local_storage::TypeTag;

    pub(super) struct Ready;
    impl TypeTag for Ready {
        type Value = ();
    }
    pub(super) struct RoundOnePrivate;
    impl TypeTag for RoundOnePrivate {
        type Value = crate::presign::round_one::Private;
    }
    pub(super) struct RoundOnePublic;
    impl TypeTag for RoundOnePublic {
        type Value = crate::presign::round_one::Public;
    }
    pub(super) struct RoundOnePublicBroadcast;
    impl TypeTag for RoundOnePublicBroadcast {
        type Value = crate::presign::round_one::PublicBroadcast;
    }
    pub(super) struct RoundTwoPrivate;
    impl TypeTag for RoundTwoPrivate {
        type Value = crate::presign::round_two::Private;
    }
    pub(super) struct RoundTwoPublic;
    impl TypeTag for RoundTwoPublic {
        type Value = crate::presign::round_two::Public;
    }
    pub(super) struct RoundThreePrivate;
    impl TypeTag for RoundThreePrivate {
        type Value = crate::presign::round_three::Private;
    }
    pub(super) struct RoundThreePublic;
    impl TypeTag for RoundThreePublic {
        type Value = crate::presign::round_three::Public;
    }
}

/// Protocol status for [`PresignParticipant`].
#[derive(Debug, PartialEq)]
pub enum Status {
    Initialized,
    TerminatedSuccessfully,
}

/// A [`ProtocolParticipant`] that runs the presign protocol[^cite].
///
/// # Protocol input
/// The protocol takes as input the following:
/// - A [`Vec`] of [`KeySharePublic`]s, which correspond to the public keyshares
///   of each participant (including this participant), and
/// - A single [`KeySharePrivate`], which corresponds to the **private**
///   keyshare of this participant.
/// - A [`Vec`] of [`AuxInfoPublic`]s, which correspond to the public auxiliary
///   information of each participant (including this participant), and
/// - A single [`AuxInfoPrivate`], which corresponds to the **private**
///   auxiliary information of this participant.
///
/// # Protocol output
/// Upon successful completion, the participant outputs the following:
/// - A single [`PresignRecord`], which corresponds to the **private** presign
///   record of this participant.
///
/// # 🔒 Storage requirement
/// The [`PresignRecord`] output requires secure persistent storage.
///
/// # 🔒 Lifetime requirement
/// The [`PresignRecord`] output must only be used once and then discarded.
///
/// [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
/// Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
/// with Identifiable Aborts. [EPrint archive,
/// 2021](https://eprint.iacr.org/2021/060.pdf). Figure 7.
#[derive(Debug)]
pub struct PresignParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    /// Broadcast subprotocol handler
    broadcast_participant: BroadcastParticipant,
    /// Status of the protocol execution
    status: Status,
}

/// Input needed for [`PresignParticipant`] to run.
#[derive(Debug, Clone)]
pub struct Input {
    /// The private keyshare of this participant.
    keyshare_private: KeySharePrivate,
    /// The public keyshares of all the participants.
    all_keyshare_public: Vec<KeySharePublic>,
    /// The private auxinfo of this participant.
    auxinfo_private: AuxInfoPrivate,
    /// The public auxinfo of all the participants.
    all_auxinfo_public: Vec<AuxInfoPublic>,
}

impl Input {
    /// Creates a new [`Input`] from the outputs of
    /// [`crate::auxinfo::participant::AuxInfoParticipant`]
    /// and [`crate::keygen::participant::KeygenParticipant`].
    pub fn new(
        all_auxinfo_public: Vec<AuxInfoPublic>,
        auxinfo_private: AuxInfoPrivate,
        all_keyshare_public: Vec<KeySharePublic>,
        keyshare_private: KeySharePrivate,
    ) -> Result<Self> {
        if all_auxinfo_public.len() != all_keyshare_public.len() {
            error!(
                "Number of auxinfo ({:?}) and keyshare ({:?}) public entries is not equal",
                all_auxinfo_public.len(),
                all_keyshare_public.len()
            );
            Err(InternalError::InternalInvariantFailed)
        } else {
            Ok(Self {
                all_auxinfo_public,
                auxinfo_private,
                all_keyshare_public,
                keyshare_private,
            })
        }
    }

    /// Returns the [`AuxInfoPublic`] associated with the given
    /// [`ParticipantIdentifier`].
    fn find_auxinfo_public(&self, pid: ParticipantIdentifier) -> Result<&AuxInfoPublic> {
        self.all_auxinfo_public
            .iter()
            .find(|item| *item.participant() == pid)
            .ok_or(InternalError::StorageItemNotFound)
    }

    /// Returns the [`KeySharePublic`] associated with the given
    /// [`ParticipantIdentifier`].
    fn find_keyshare_public(&self, pid: ParticipantIdentifier) -> Result<&KeySharePublic> {
        self.all_keyshare_public
            .iter()
            .find(|item| item.participant() == pid)
            .ok_or(InternalError::StorageItemNotFound)
    }

    /// Returns the [`AuxInfoPublic`]s associated with all the participants
    /// _except_ the given [`ParticipantIdentifier`].
    fn all_but_one_auxinfo_public(&self, pid: ParticipantIdentifier) -> Vec<&AuxInfoPublic> {
        self.all_auxinfo_public
            .iter()
            .filter(|item| *item.participant() != pid)
            .collect()
    }
}

impl ProtocolParticipant for PresignParticipant {
    type Input = Input;
    type Output = PresignRecord;
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
        MessageType::Presign(PresignMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Presign
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &Vec<ParticipantIdentifier> {
        &self.other_participant_ids
    }

    /// Processes the incoming message given the storage from the protocol
    /// participant (containing auxinfo and keygen artifacts). Optionally
    /// produces a [`PresignRecord`] once presigning is complete.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Self::Input,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing presign message.");

        if *self.status() == Status::TerminatedSuccessfully {
            return Err(InternalError::ProtocolAlreadyTerminated);
        }

        match message.message_type() {
            MessageType::Presign(PresignMessageType::Ready) => {
                self.handle_ready_msg(rng, message, input)
            }
            MessageType::Presign(PresignMessageType::RoundOneBroadcast) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_broadcast_msg, rng, input)
            }
            MessageType::Presign(PresignMessageType::RoundOne) => {
                self.handle_round_one_msg(rng, message, input)
            }
            MessageType::Presign(PresignMessageType::RoundTwo) => {
                self.handle_round_two_msg(rng, message, input)
            }
            MessageType::Presign(PresignMessageType::RoundThree) => {
                self.handle_round_three_msg(rng, message, input)
            }

            _ => Err(InternalError::MisroutedMessage),
        }
    }

    fn status(&self) -> &Self::Status {
        &self.status
    }
}

impl InnerProtocolParticipant for PresignParticipant {
    type Context = Vec<ParticipantIdentifier>;

    fn retrieve_context(&self) -> <Self as InnerProtocolParticipant>::Context {
        let mut ids = self.all_participants();
        ids.sort();
        ids
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.local_storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.local_storage
    }
}

impl Broadcast for PresignParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl PresignParticipant {
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling ready presign message.");

        let (ready_outcome, is_ready) = self.process_ready_message::<storage::Ready>(message)?;

        if is_ready {
            let round_one_outcome = self.gen_round_one_msgs(rng, message, input)?;
            ready_outcome.consolidate(vec![round_one_outcome])
        } else {
            Ok(ready_outcome)
        }
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
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Generating round one presign messages.");

        // Reconstruct keyshare and other participants' public keyshares from local
        // storage
        let keyshare = get_keyshare(self.id, input)?;
        let other_public_auxinfo = input.all_but_one_auxinfo_public(self.id);

        // Run Round One
        let (private, r1_publics, r1_public_broadcast) =
            keyshare.round_one(rng, &self.retrieve_context(), &other_public_auxinfo)?;

        // Store private round one value locally
        self.local_storage
            .store::<storage::RoundOnePrivate>(self.id, private);

        // Publish public round one value to all other participants on the channel
        let non_broadcast_messages = r1_publics
            .into_iter()
            .map(|(other_id, r1_public)| {
                Ok(Message::new(
                    MessageType::Presign(PresignMessageType::RoundOne),
                    message.id(),
                    self.id,
                    other_id,
                    &serialize!(&r1_public)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        let broadcast_messages = self.broadcast(
            rng,
            MessageType::Presign(PresignMessageType::RoundOneBroadcast),
            serialize!(&r1_public_broadcast)?,
            message.id(),
            BroadcastTag::PresignR1Ciphertexts,
        )?;

        // Additionally, handle any round 1 messages which may have been received too
        // early
        let retrieved_messages =
            self.fetch_messages(MessageType::Presign(PresignMessageType::RoundOne))?;
        let round_two_outcomes = retrieved_messages
            .iter()
            .map(|msg| self.handle_round_one_msg(rng, msg, input))
            .collect::<Result<Vec<_>>>()?;

        Ok(ProcessOutcome::collect(round_two_outcomes)?
            .with_messages(broadcast_messages)
            .with_messages(non_broadcast_messages))
    }

    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_broadcast_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: &BroadcastOutput,
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        if broadcast_message.tag != BroadcastTag::PresignR1Ciphertexts {
            error!("Incorrect tag for Presign R1 Broadcast!");
            return Err(InternalError::IncorrectBroadcastMessageTag);
        }
        let message = &broadcast_message.msg;
        let public_broadcast: RoundOnePublicBroadcast = deserialize!(&message.unverified_bytes)?;
        self.local_storage
            .store::<storage::RoundOnePublicBroadcast>(message.from(), public_broadcast);

        // Check to see if we have already stored the other part of round one. If so,
        // retrieve and process it
        let retrieved_messages = self.fetch_messages_by_sender(
            MessageType::Presign(PresignMessageType::RoundOne),
            message.from(),
        )?;
        let non_broadcasted_portion = match retrieved_messages.get(0) {
            Some(message) => message,
            None => return Ok(ProcessOutcome::Incomplete),
        };
        self.handle_round_one_msg(rng, non_broadcasted_portion, input)
    }

    /// Processes a single request from round one to create public keyshares for
    /// that participant, to be sent in round two.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round one presign message.");

        // Check if we have both have received the broadcasted ciphertexts that we need
        // in order to respond and have started round one
        if !(self
            .local_storage
            .contains::<storage::RoundOnePublicBroadcast>(message.from())
            && self
                .local_storage
                .contains::<storage::RoundOnePrivate>(message.to()))
        {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        self.gen_round_two_msg(rng, message, input)
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
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Generating round two presign messages.");
        // Reconstruct keyshare and other participants' public keyshares from local
        // storage
        let keyshare = get_keyshare(self.id, input)?;

        // Find the keyshare corresponding to the "from" participant
        let keyshare_from = input.find_auxinfo_public(message.from())?;

        // Get this participant's round 1 private value
        let r1_priv = self
            .local_storage
            .retrieve::<storage::RoundOnePrivate>(message.to())?;
        let r1_priv = r1_priv.clone();

        // Get the round one message broadcasted by this sender
        let r1_public_broadcast = self
            .local_storage
            .retrieve::<storage::RoundOnePublicBroadcast>(message.from())?;
        let r1_public_broadcast = r1_public_broadcast.clone();

        let r1_public = crate::round_one::Public::from_message(
            message,
            &self.retrieve_context(),
            &keyshare.aux_info_public,
            keyshare_from,
            &r1_public_broadcast,
        )?;

        // Store the round 1 public value
        self.local_storage
            .store::<storage::RoundOnePublic>(message.from(), r1_public);

        let (r2_priv_ij, r2_pub_ij) = keyshare.round_two(
            rng,
            &self.retrieve_context(),
            keyshare_from,
            &r1_priv,
            &r1_public_broadcast,
        )?;

        // Store the private value for this round 2 pair
        self.local_storage
            .store::<storage::RoundTwoPrivate>(message.from(), r2_priv_ij);

        let round_one_message = vec![Message::new(
            MessageType::Presign(PresignMessageType::RoundTwo),
            message.id(),
            self.id,
            message.from(), // This is a essentially response to that sender
            &serialize!(&r2_pub_ij)?,
        )];

        // Check if there's a round 2 message that this now allows us to process
        let retrieved_messages = self.fetch_messages_by_sender(
            MessageType::Presign(PresignMessageType::RoundTwo),
            message.from(),
        )?;

        let round_two_outcomes = retrieved_messages
            .iter()
            .map(|msg| self.handle_round_two_msg(rng, msg, input))
            .collect::<Result<Vec<_>>>()?;

        if round_two_outcomes.len() > 1 {
            // There should never be more than one round 2 message from a single party
            error!(
                "Received multiple ({}) round 2 messages from {}. Expected one.",
                round_two_outcomes.len(),
                message.from()
            );
            Err(InternalError::ProtocolError)
        } else {
            ProcessOutcome::collect_with_messages(round_two_outcomes, round_one_message)
        }
    }

    /// Process a single request from round two
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round two presign message.");

        // First, check that the sender's Round One messages have been processed
        if !self
            .local_storage
            .contains::<storage::RoundOnePublic>(message.from())
        {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        // Verify the bytes of the round two value, and store it locally.
        self.validate_and_store_round_two_public(input, message)?;

        // Check if storage has all of the other participants' round 2 values (both
        // private and public), and start generating the messages for round 3 if so
        let all_privates_received = self
            .local_storage
            .contains_for_all_ids::<storage::RoundTwoPrivate>(&self.other_participant_ids);
        let all_publics_received = self
            .local_storage
            .contains_for_all_ids::<storage::RoundTwoPublic>(&self.other_participant_ids);
        if all_privates_received && all_publics_received {
            self.gen_round_three_msgs(rng, message, input)
        } else {
            Ok(ProcessOutcome::Incomplete)
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
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Generating round three presign messages.");

        // Reconstruct keyshare from local storage
        let keyshare = get_keyshare(self.id, input)?;

        let round_three_hashmap = self.get_other_participants_round_three_values(input)?;

        // Get this participant's round 1 private value
        let r1_priv = self
            .local_storage
            .retrieve::<storage::RoundOnePrivate>(self.id)?;

        let (r3_private, r3_publics_map) =
            keyshare.round_three(rng, &self.retrieve_context(), r1_priv, &round_three_hashmap)?;

        // Store round 3 private value
        self.local_storage
            .store::<storage::RoundThreePrivate>(self.id, r3_private);

        // Publish public r3 values to all other participants on the channel
        let round_two_messages = r3_publics_map
            .into_iter()
            .map(|(id, r3_public)| {
                Ok(Message::new(
                    MessageType::Presign(PresignMessageType::RoundThree),
                    message.id(),
                    self.id,
                    id,
                    &serialize!(&r3_public)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        // Additionally, handle any round 3 messages which may have been received too
        // early
        let retrieved_messages =
            self.fetch_messages(MessageType::Presign(PresignMessageType::RoundThree))?;
        let round_three_outcomes = retrieved_messages
            .iter()
            .map(|msg| self.handle_round_three_msg(rng, msg, input))
            .collect::<Result<Vec<_>>>()?;

        ProcessOutcome::collect_with_messages(round_three_outcomes, round_two_messages)
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        message: &Message,
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round three presign message.");

        // If we have not yet started round three, stash the message for later
        let r3_started = self
            .local_storage
            .retrieve::<storage::RoundThreePrivate>(self.id)
            .is_ok();
        if !r3_started {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        // First, verify and store the round three value locally
        self.validate_and_store_round_three_public(input, message)?;

        if self
            .local_storage
            .contains_for_all_ids::<storage::RoundThreePublic>(&self.other_participant_ids)
        {
            let record = self.do_presign_finish()?;
            self.status = Status::TerminatedSuccessfully;
            Ok(ProcessOutcome::Terminated(record))
        } else {
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Presign: Finish
    ///
    /// In this step, the participant simply collects all r3 public values and
    /// its r3 private value, and assembles them into a PresignRecord.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn do_presign_finish(&mut self) -> Result<PresignRecord> {
        info!("Doing presign finish. Creating presign record.");
        let r3_pubs = self.get_other_participants_round_three_publics()?;

        // Get this participant's round 3 private value
        let r3_private = self
            .local_storage
            .retrieve::<storage::RoundThreePrivate>(self.id)?;

        // Check consistency across all Gamma values
        for (i, r3_pub) in r3_pubs.iter().enumerate() {
            if r3_pub.Gamma != r3_private.Gamma {
                error!(
                    "Mismatch in Gamma values for r3_private and the r3_pub of participant: {:?}",
                    &self.other_participant_ids[i]
                );
                return Err(InternalError::ProtocolError);
            }
        }

        let presign_record: PresignRecord = RecordPair {
            private: r3_private.clone(),
            publics: r3_pubs,
        }
        .try_into()?;

        Ok(presign_record)
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn validate_and_store_round_two_public(
        &mut self,
        input: &Input,
        message: &Message,
    ) -> Result<()> {
        let receiver_auxinfo_public = input.find_auxinfo_public(message.to())?;
        let sender_auxinfo_public = input.find_auxinfo_public(message.from())?;
        let sender_keyshare_public = input.find_keyshare_public(message.from())?;
        let receiver_r1_private = self
            .local_storage
            .retrieve::<storage::RoundOnePrivate>(message.to())?;
        let sender_r1_public_broadcast = self
            .local_storage
            .retrieve::<storage::RoundOnePublicBroadcast>(message.from())?;

        let round_two_public = crate::round_two::Public::from_message(
            message,
            &self.retrieve_context(),
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_keyshare_public,
            receiver_r1_private,
            sender_r1_public_broadcast,
        )?;

        self.local_storage
            .store::<storage::RoundTwoPublic>(message.from(), round_two_public);

        Ok(())
    }
    /// `auxinfo_identifier` corresponds to a unique session identifier.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn validate_and_store_round_three_public(
        &mut self,
        input: &Input,
        message: &Message,
    ) -> Result<()> {
        let receiver_auxinfo_public = input.find_auxinfo_public(message.to())?;
        let sender_auxinfo_public = input.find_auxinfo_public(message.from())?;
        let sender_r1_public_broadcast = self
            .local_storage
            .retrieve::<storage::RoundOnePublicBroadcast>(message.from())?;

        let public_message = crate::round_three::Public::from_message(
            message,
            &self.retrieve_context(),
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_r1_public_broadcast,
        )?;

        self.local_storage
            .store::<storage::RoundThreePublic>(message.from(), public_message);

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
    /// `auxinfo_identifier` and `identifier` correspond to unique session
    /// identifiers.
    fn get_other_participants_round_three_values(
        &self,
        input: &Input,
    ) -> Result<HashMap<ParticipantIdentifier, RoundThreeInput>> {
        // begin by checking Storage contents to ensure we're ready for round three
        if !self
            .local_storage
            .contains_for_all_ids::<storage::RoundTwoPrivate>(&self.other_participant_ids)
            || !self
                .local_storage
                .contains_for_all_ids::<storage::RoundTwoPublic>(&self.other_participant_ids)
        {
            return Err(InternalError::StorageItemNotFound);
        }

        let mut hm = HashMap::new();
        for other_participant_id in self.other_participant_ids.clone() {
            let auxinfo_public = input.find_auxinfo_public(other_participant_id)?;
            let r2_private = self
                .local_storage
                .retrieve::<storage::RoundTwoPrivate>(other_participant_id)?;
            let r2_public = self
                .local_storage
                .retrieve::<storage::RoundTwoPublic>(other_participant_id)?;
            let _ = hm.insert(
                other_participant_id,
                RoundThreeInput {
                    auxinfo_public: auxinfo_public.clone(),
                    r2_private: r2_private.clone(),
                    r2_public: r2_public.clone(),
                },
            );
        }
        Ok(hm)
    }

    /// Aggregate the other participants' round three public values from
    /// storage. But don't remove them from storage.
    ///
    /// This returns a Vec with the values.
    /// `identifier` here correspond to a unique session identifier.
    fn get_other_participants_round_three_publics(
        &self,
    ) -> Result<Vec<crate::round_three::Public>> {
        if !self
            .local_storage
            .contains_for_all_ids::<storage::RoundThreePublic>(&self.other_participant_ids)
        {
            return Err(InternalError::StorageItemNotFound);
        }
        let ret_vec = self
            .other_participant_ids
            .iter()
            .map(|other_participant_id| {
                let r3pub = self
                    .local_storage
                    .retrieve::<storage::RoundThreePublic>(*other_participant_id)?;
                Ok(r3pub.clone())
            })
            .collect::<Result<Vec<crate::round_three::Public>>>()?;
        Ok(ret_vec)
    }
}

/// `auxinfo_identifier` and `keyshare_identifier` correspond to unique session
/// identifiers.
pub(crate) fn get_keyshare(
    self_id: ParticipantIdentifier,
    input: &Input,
) -> Result<PresignKeyShareAndInfo> {
    // Reconstruct keyshare from local storage
    let keyshare_and_info = PresignKeyShareAndInfo {
        aux_info_private: input.auxinfo_private.clone(),
        aux_info_public: input.find_auxinfo_public(self_id)?.clone(),
        keyshare_private: input.keyshare_private.clone(),
        keyshare_public: input.find_keyshare_public(self_id)?.clone(),
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
        context: &impl ProofContext,
        public_keys: &[&AuxInfoPublic],
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
        let (K, rho) = self.aux_info_public.pk().encrypt(rng, &k)?;
        // Sample nu <- Z_N^* and set G = enc(gamma; nu)
        let (G, nu) = self.aux_info_public.pk().encrypt(rng, &gamma)?;

        let mut r1_publics = HashMap::new();
        for aux_info_public in public_keys {
            // Compute psi_{j,i} for every participant j != i
            let mut transcript = Transcript::new(b"PiEncProof");
            let proof = PiEncProof::prove(
                &crate::zkp::pienc::PiEncInput::new(
                    aux_info_public.params().clone(),
                    self.aux_info_public.pk().clone(),
                    K.clone(),
                ),
                &crate::zkp::pienc::PiEncSecret::new(k.clone(), rho.clone()),
                context,
                &mut transcript,
                rng,
            )?;
            let r1_public = RoundOnePublic { proof };
            let _ = r1_publics.insert(*aux_info_public.participant(), r1_public);
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
        context: &impl ProofContext,
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
        let (beta_ciphertext, s) = receiver_aux_info.pk().encrypt(rng, &beta)?;
        let (beta_hat_ciphertext, s_hat) = receiver_aux_info.pk().encrypt(rng, &beta_hat)?;

        let D = receiver_aux_info.pk().multiply_and_add(
            &sender_r1_priv.gamma,
            &receiver_r1_pub_broadcast.K,
            &beta_ciphertext,
        )?;
        let D_hat = receiver_aux_info.pk().multiply_and_add(
            &self.keyshare_private.x,
            &receiver_r1_pub_broadcast.K,
            &beta_hat_ciphertext,
        )?;
        let (F, r) = self.aux_info_public.pk().encrypt(rng, &beta)?;
        let (F_hat, r_hat) = self.aux_info_public.pk().encrypt(rng, &beta_hat)?;

        let g = CurvePoint::GENERATOR;
        let Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma)?);

        // Generate three proofs
        let mut transcript = Transcript::new(b"PiAffgProof");

        let psi = PiAffgProof::prove(
            &PiAffgInput::new(
                receiver_aux_info.params(),
                &g,
                receiver_aux_info.pk(),
                self.aux_info_public.pk(),
                &receiver_r1_pub_broadcast.K,
                &D,
                &F,
                &Gamma,
            ),
            &PiAffgSecret::new(&sender_r1_priv.gamma, &beta, &s, &r),
            context,
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiAffgProof");

        let psi_hat = PiAffgProof::prove(
            &PiAffgInput::new(
                receiver_aux_info.params(),
                &g,
                receiver_aux_info.pk(),
                self.aux_info_public.pk(),
                &receiver_r1_pub_broadcast.K,
                &D_hat,
                &F_hat,
                &self.keyshare_public.X,
            ),
            &PiAffgSecret::new(&self.keyshare_private.x, &beta_hat, &s_hat, &r_hat),
            context,
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiLogProof");
        let psi_prime = PiLogProof::prove(
            &CommonInput::new(
                sender_r1_priv.G.clone(),
                Gamma,
                receiver_aux_info.params().scheme().clone(),
                self.aux_info_public.pk().clone(),
                g,
            ),
            &ProverSecret::new(sender_r1_priv.gamma.clone(), sender_r1_priv.nu.clone()),
            context,
            &mut transcript,
            rng,
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
        context: &impl ProofContext,
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

            let alpha = self
                .aux_info_private
                .decryption_key()
                .decrypt(&r2_pub_j.D)?;
            let alpha_hat = self
                .aux_info_private
                .decryption_key()
                .decrypt(&r2_pub_j.D_hat)?;

            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);
            Gamma = CurvePoint(Gamma.0 + r2_pub_j.Gamma.0);
        }

        let Delta = CurvePoint(Gamma.0 * bn_to_scalar(&sender_r1_priv.k)?);

        let delta_scalar = bn_to_scalar(&delta)?;
        let chi_scalar = bn_to_scalar(&chi)?;

        let mut ret_publics = HashMap::new();
        for (other_id, round_three_input) in other_participant_inputs {
            let mut transcript = Transcript::new(b"PiLogProof");
            let psi_double_prime = PiLogProof::prove(
                &CommonInput::new(
                    sender_r1_priv.K.clone(),
                    Delta,
                    round_three_input.auxinfo_public.params().scheme().clone(),
                    self.aux_info_public.pk().clone(),
                    Gamma,
                ),
                &ProverSecret::new(sender_r1_priv.k.clone(), sender_r1_priv.rho.clone()),
                context,
                &mut transcript,
                rng,
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
