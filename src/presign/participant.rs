//! Types and functions related to the pre-signing sub-protocol Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::{AuxInfoPrivate, AuxInfoPublic},
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    keygen::{KeySharePrivate, KeySharePublic},
    local_storage::LocalStorage,
    messages::{Message, MessageType, PresignMessageType},
    parameters::ELL_PRIME,
    participant::{Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    presign::{
        input::Input,
        record::{PresignRecord, RecordPair},
        round_one, round_three, round_two,
    },
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    run_only_once,
    utils::{random_plusminus_by_size, random_positive_bn},
    zkp::{
        piaffg::{PiAffgInput, PiAffgProof, PiAffgSecret},
        pienc::{PiEncInput, PiEncProof, PiEncSecret},
        pilog::{CommonInput, PiLogProof, ProverSecret},
        Proof, ProofContext,
    },
    Identifier,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::collections::{HashMap, HashSet};
use tracing::{error, info, instrument};

// Local storage data types.
mod storage {
    use std::marker::PhantomData;

    use crate::{curve::CurveTrait, local_storage::TypeTag};

    pub(super) struct RoundOnePrivate;
    impl TypeTag for RoundOnePrivate {
        type Value = crate::presign::round_one::Private;
    }
    pub(super) struct RoundOneComplete;
    impl TypeTag for RoundOneComplete {
        type Value = ();
    }
    pub(super) struct RoundOnePublicBroadcast;
    impl TypeTag for RoundOnePublicBroadcast {
        type Value = crate::presign::round_one::PublicBroadcast;
    }
    pub(super) struct RoundTwoPrivate;
    impl TypeTag for RoundTwoPrivate {
        type Value = crate::presign::round_two::Private;
    }
    pub(super) struct RoundTwoPublic<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for RoundTwoPublic<C> {
        type Value = crate::presign::round_two::Public<C>;
    }
    pub(super) struct RoundThreePrivate<C>(PhantomData<C>);
    impl<C: CurveTrait + Send + Sync> TypeTag for RoundThreePrivate<C> {
        type Value = crate::presign::round_three::Private<C>;
    }
    pub(super) struct RoundThreePublic<C>(PhantomData<C>);
    impl<C: CurveTrait + Send + Sync> TypeTag for RoundThreePublic<C> {
        type Value = crate::presign::round_three::Public<C>;
    }
}

/// This type includes relevant context for transcripts produced in `presign`,
/// and includes [`SharedContext`] and [`AuxInfoPublic`]s for all participants
/// (including this participant).
#[derive(Debug)]
pub(crate) struct PresignContext<C: CurveTrait> {
    shared_context: SharedContext<C>,
    rid: [u8; 32],
    auxinfo_public: Vec<AuxInfoPublic>,
}

impl<C: CurveTrait> ProofContext for PresignContext<C> {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok([
            self.shared_context.as_bytes()?,
            self.rid[..].to_vec(),
            bincode::serialize(&self.auxinfo_public)
                .map_err(|_| InternalError::InternalInvariantFailed)?,
        ]
        .concat())
    }
}

impl<C: CurveTrait> PresignContext<C> {
    /// Build a [`PresignContext`] from a [`PresignParticipant`].
    pub(crate) fn collect(p: &PresignParticipant<C>) -> Self {
        let mut auxinfo_public = p.input().to_public_auxinfo();
        auxinfo_public.sort_by_key(AuxInfoPublic::participant);
        Self {
            shared_context: SharedContext::collect(p),
            rid: *p.input().rid(),
            auxinfo_public,
        }
    }

    fn for_participant(self, pid: ParticipantIdentifier) -> ParticipantPresignContext<C> {
        ParticipantPresignContext {
            presign_context: self,
            participant_id: pid,
        }
    }
}

pub struct ParticipantPresignContext<C: CurveTrait> {
    presign_context: PresignContext<C>,
    participant_id: ParticipantIdentifier,
}

impl<C: CurveTrait> ProofContext for ParticipantPresignContext<C> {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok([
            self.presign_context.as_bytes()?,
            bincode::serialize(&self.participant_id)
                .map_err(|_| InternalError::InternalInvariantFailed)?,
        ]
        .concat())
    }
}

/// A [`ProtocolParticipant`] that runs the presign protocol.
///
/// # Protocol input
/// The protocol takes an [`Input`] which includes:
/// - The [`Output`](crate::keygen::Output) of a [`keygen`](crate::keygen)
///   protocol execution
///   - A list of [public key shares](KeySharePublic), one for each participant
///     (including this participant);
///   - A single [private key share](KeySharePrivate) for this participant; and
///   - A random value, agreed on by all participants.
/// - The [`Output`](crate::auxinfo::Output) of an [`auxinfo`](crate::auxinfo)
///   protocol execution
///   - A list of [public auxiliary information](AuxInfoPublic), one for each
///     participant (including this participant), and
///   - A single set of [private auxiliary information](`AuxInfoPrivate`) for
///     this participant.
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
#[derive(Debug)]
pub struct PresignParticipant<C: CurveTrait> {
    /// The current session identifier.
    sid: Identifier,
    /// The current protocol input.
    input: Input<C>,
    /// A unique identifier for this participant.
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol.
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets.
    local_storage: LocalStorage,
    /// Broadcast subprotocol handler.
    broadcast_participant: BroadcastParticipant<C>,
    /// Status of the protocol execution.
    status: Status,
}

impl<C: CurveTrait> ProtocolParticipant for PresignParticipant<C> {
    type Input = Input<C>;
    type Output = PresignRecord<C>;

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self> {
        let input_participants = input.participants();

        // Check that we have the expected number of inputs
        if input_participants.len() != other_participant_ids.len() + 1 {
            error!(
                "Size of the input ({}) doesn't match size of the participant set ({})",
                input_participants.len(),
                other_participant_ids.len() + 1
            );
            Err(CallerError::BadInput)?;
        }

        // Make sure the inputs belong to the specified participant set: first define
        // the two sets...
        let input_set = HashSet::<&ParticipantIdentifier>::from_iter(input_participants.iter());
        let mut participants = HashSet::from_iter(other_participant_ids.iter());
        let _inserted = participants.insert(&id);

        // ...then make sure they match.
        if participants != input_set {
            error!("The provided inputs are not from the specified set of participants");
            Err(CallerError::BadInput)?;
        }

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
        MessageType::Presign(PresignMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Presign
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

    /// Process the incoming message.
    ///
    /// This method produces a [`PresignRecord`] once presigning is complete.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing presign message.");

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
        }

        if !self.status().is_ready() && message.message_type() != Self::ready_type() {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        match message.message_type() {
            MessageType::Presign(PresignMessageType::Ready) => self.handle_ready_msg(rng, message),
            MessageType::Presign(PresignMessageType::RoundOneBroadcast) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_broadcast_msg, rng)
            }
            MessageType::Presign(PresignMessageType::RoundOne) => {
                self.handle_round_one_msg(rng, message)
            }
            MessageType::Presign(PresignMessageType::RoundTwo) => {
                self.handle_round_two_msg(rng, message)
            }
            MessageType::Presign(PresignMessageType::RoundThree) => {
                self.handle_round_three_msg(message)
            }
            message_type => {
                error!(
                    "Incorrect MessageType given to PresignParticipant. Got: {:?}",
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

impl<C: CurveTrait> InnerProtocolParticipant for PresignParticipant<C> {
    type Context = PresignContext<C>;

    fn retrieve_context(&self) -> <Self as InnerProtocolParticipant>::Context {
        PresignContext::collect(self)
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

impl<C: CurveTrait> Broadcast<C> for PresignParticipant<C> {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant<C> {
        &mut self.broadcast_participant
    }
}

impl<C: CurveTrait> PresignParticipant<C> {
    fn input(&self) -> &Input<C> {
        &self.input
    }

    /// Handle "Ready" messages from the protocol participants.
    ///
    /// Once "Ready" messages have been received from all participants, this
    /// method triggers this participant to generate its round one messages.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling ready presign message.");

        let ready_outcome = self.process_ready_message(rng, message)?;
        let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, message.id()))?;
        // extend the output with r1 messages (if they hadn't already been generated)
        Ok(ready_outcome.with_messages(round_one_messages))
    }

    /// Generate this participant's round one messages.
    ///
    /// In this round, each participant generates some local shares, encrypts
    /// them using the Paillier encryption scheme generated during `auxinfo`,
    /// and produces a proof (to each other participant) that the encryption was
    /// done correctly. It broadcasts the encrypted local shares, and sends each
    /// proof to its respective participant.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one presign messages.");

        let info = PresignKeyShareAndInfo::new(self.id, self.input())?;
        let other_public_auxinfo = self.input().all_but_one_auxinfo_public(self.id);

        // Run round one.
        let (private, r1_publics, r1_public_broadcast) = info.round_one(
            rng,
            &self.retrieve_context().for_participant(self.id()),
            &other_public_auxinfo,
        )?;

        // Store private round one value locally.
        self.local_storage
            .store::<storage::RoundOnePrivate>(self.id, private);

        // Generate round one messages for all other participants.
        let mut messages = r1_publics
            .into_iter()
            .map(|(other_id, r1_public)| {
                Message::new(
                    MessageType::Presign(PresignMessageType::RoundOne),
                    sid,
                    self.id,
                    other_id,
                    &r1_public,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        // Generate the round one broadcast messages.
        let broadcast_messages = self.broadcast(
            rng,
            MessageType::Presign(PresignMessageType::RoundOneBroadcast),
            serialize!(&r1_public_broadcast)?,
            sid,
            BroadcastTag::PresignR1Ciphertexts,
        )?;
        messages.extend(broadcast_messages);
        Ok(messages)
    }

    /// Handle a round one broadcast message from another participant.
    ///
    /// This stores the broadcast message and checks if the non-broadcast
    /// message from the given participant has been received. If so, it
    /// handles that message.
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_broadcast_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: BroadcastOutput,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        let message = broadcast_message.into_message(BroadcastTag::PresignR1Ciphertexts)?;

        self.check_for_duplicate_msg::<storage::RoundOnePublicBroadcast>(message.from())?;
        info!("Presign: Handling round one broadcast message.");

        let public_broadcast: round_one::PublicBroadcast = deserialize!(&message.unverified_bytes)?;
        self.local_storage
            .store_once::<storage::RoundOnePublicBroadcast>(message.from(), public_broadcast)?;

        // Check to see if we have already stored the round one non-broadcast
        // message from the given participant. If so, retrieve and process it.
        let retrieved_messages = self.fetch_messages_by_sender(
            MessageType::Presign(PresignMessageType::RoundOne),
            message.from(),
        )?;
        // We should only have one such non-broadcast message. If we have more
        // than one that's a problem.
        if retrieved_messages.len() > 1 {
            error!(
                "Received more than one presign round one message from sender {}.",
                message.from()
            );
            return Err(InternalError::ProtocolError(None));
        }
        match retrieved_messages.first() {
            Some(message) => self.handle_round_one_msg(rng, message),
            None => Ok(ProcessOutcome::Incomplete),
        }
    }

    /// Handle a round one non-broadcast message from another participant.
    ///
    /// This checks if we've received the associated broadcast message from that
    /// participant, and if so proceeds to generate round two messages.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::RoundOneComplete>(message.from())?;
        info!("Presign: Handling round one message.");

        // First check that we have the round one public broadcast from this
        // participant. If not, we cannot proceed, so stash that message.
        if !self
            .local_storage
            .contains::<storage::RoundOnePublicBroadcast>(message.from())
        {
            info!("Presign: Stashing early round one message (no matching broadcast message).");
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        // Now that we know local storage contains the entry we can retrieve it.
        // Note that the reason we do _not_ use the output of `retrieve` to make
        // this decision is that `retrieve` can either error out because an
        // entry isn't there, _or_ because of an internal invariant failure.
        let r1_public_broadcast = self
            .local_storage
            .retrieve::<storage::RoundOnePublicBroadcast>(message.from())?;

        let info = PresignKeyShareAndInfo::new(self.id, self.input())?;
        let auxinfo_public = self.input().find_auxinfo_public(message.from())?;
        let round_one_public = round_one::Public::try_from(message)?;
        round_one_public.verify(
            &self.retrieve_context().for_participant(message.from()),
            info.aux_info_public.params(),
            auxinfo_public.pk(),
            r1_public_broadcast,
        )?;
        // Mark that we have completed round one for this participant.
        //
        // Since we don't need the round one message in the rest of the
        // protocol, we don't need to store it in storage.
        self.local_storage
            .store_once::<storage::RoundOneComplete>(message.from(), ())?;
        // Check if we're done with round one by checking that we're done with
        // round one for all other participants.
        if self
            .local_storage
            .contains_for_all_ids::<storage::RoundOneComplete>(&self.other_participant_ids)
        {
            info!("Presign: Round one complete. Generating round two messages.");
            // Finish round one by generating messages for round two.
            let round_two_messages = run_only_once!(self.gen_round_two_msgs(rng, message.id()))?;
            // Process any round two messages we may have received early.
            let round_two_outcomes = self
                .fetch_messages(MessageType::Presign(PresignMessageType::RoundTwo))?
                .iter()
                .map(|msg| self.handle_round_two_msg(rng, msg))
                .collect::<Result<Vec<_>>>()?;
            ProcessOutcome::collect_with_messages(round_two_outcomes, round_two_messages)
        } else {
            info!("Presign: Round one incomplete.");
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate round two messages.
    ///
    /// This generates the "masked" exponent share and "masked" private key
    /// share, alongside the relevant zero-knowledge proofs.
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Presign: Generating round two messages.");

        let mut messages = vec![];
        // Check that we've generated round one messages by checking that our
        // round one private value exists. If not, generate those messages first
        // before proceeding to the round two message generation.
        if !self
            .local_storage
            .contains::<storage::RoundOnePrivate>(self.id)
        {
            let more_messages = run_only_once!(self.gen_round_one_msgs(rng, sid))?;
            messages.extend_from_slice(&more_messages);
        }

        let info = PresignKeyShareAndInfo::new(self.id, self.input())?;
        // We need this clone as the map below uses a mutable `self`.
        let pids = self.other_participant_ids.clone();
        let more_messages: Vec<Message> = pids
            .into_iter()
            .map(|pid| {
                let r1_priv = self
                    .local_storage
                    .retrieve::<storage::RoundOnePrivate>(self.id)?;
                let r1_public_broadcast = self
                    .local_storage
                    .retrieve::<storage::RoundOnePublicBroadcast>(pid)?;
                let sender_auxinfo_public = self.input().find_auxinfo_public(pid)?;
                let (r2_priv, r2_pub) = info.round_two(
                    rng,
                    &self.retrieve_context().for_participant(self.id()),
                    sender_auxinfo_public,
                    r1_priv,
                    r1_public_broadcast,
                )?;
                self.local_storage
                    .store::<storage::RoundTwoPrivate>(pid, r2_priv);
                Message::new(
                    MessageType::Presign(PresignMessageType::RoundTwo),
                    sid,
                    self.id,
                    pid,
                    &r2_pub,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        messages.extend(more_messages);
        Ok(messages)
    }

    /// Handle a round two message.
    ///
    /// This verifies that the three proofs associated with the round two
    /// message are all valid.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Presign: Handling round two message.");

        // We must have completed round one for all participants before we
        // can proceed to round two.
        if !self
            .local_storage
            .contains_for_all_ids::<storage::RoundOneComplete>(&self.other_participant_ids)
        {
            info!("Presign: Not done with round one. Stashing message.");
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        self.validate_and_store_round_two_public(message)?;

        // Check if storage has all of the other participants' round two values
        // (both private and public), and start generating the messages for
        // round three if so.
        let all_privates_received = self
            .local_storage
            .contains_for_all_ids::<storage::RoundTwoPrivate>(&self.other_participant_ids);
        let all_publics_received = self
            .local_storage
            .contains_for_all_ids::<storage::RoundTwoPublic<C>>(&self.other_participant_ids);
        if all_privates_received && all_publics_received {
            info!("Presign: Round two complete. Generating round three messages.");
            // Generate messages for round three...
            let messages = run_only_once!(self.gen_round_three_msgs(rng, message.id()))?;
            // ... and handle any messages that other participants have sent for round
            // three.
            let outcomes = self
                .fetch_messages(MessageType::Presign(PresignMessageType::RoundThree))?
                .iter()
                .map(|msg| self.handle_round_three_msg(msg))
                .collect::<Result<Vec<_>>>()?;
            ProcessOutcome::collect_with_messages(outcomes, messages)
        } else {
            info!("Presign: Round two incomplete.");
            // Otherwise, wait for more round two messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate round three messages.
    ///
    /// This round generates the "unmasked" combined exponent shares and
    /// "unmasked" combined private key shares, alongside any associated
    /// zero-knowledge proofs.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round three presign messages.");

        let info = PresignKeyShareAndInfo::new(self.id, self.input())?;
        // Collect the other participant's values from storage needed for round
        // three.
        let mut hashmap = HashMap::new();
        for pid in self.other_participant_ids.clone() {
            let auxinfo_public = self.input().find_auxinfo_public(pid)?;
            let r2_private = self
                .local_storage
                .retrieve::<storage::RoundTwoPrivate>(pid)?;
            let r2_public = self
                .local_storage
                .retrieve::<storage::RoundTwoPublic<C>>(pid)?;
            let _ = hashmap.insert(
                pid,
                round_three::Input {
                    auxinfo_public: auxinfo_public.clone(),
                    r2_private: r2_private.clone(),
                    r2_public: r2_public.clone(),
                },
            );
        }

        let r1_priv = self
            .local_storage
            .retrieve::<storage::RoundOnePrivate>(self.id)?;

        let (r3_private, r3_publics_map) = info.round_three(
            rng,
            &self.retrieve_context().for_participant(self.id()),
            r1_priv,
            &hashmap,
        )?;

        self.local_storage
            .store::<storage::RoundThreePrivate<C>>(self.id, r3_private);

        let messages = r3_publics_map
            .into_iter()
            .map(|(id, r3_public)| {
                Message::new(
                    MessageType::Presign(PresignMessageType::RoundThree),
                    sid,
                    self.id,
                    id,
                    &r3_public,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(messages)
    }

    /// Handle a round three message.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round three presign message.");

        // If we have not yet started round three, stash the message for later.
        // We check that we've started round three by checking whether our own
        // private round three value exists in storage.
        if !self
            .local_storage
            .contains::<storage::RoundThreePrivate<C>>(self.id)
        {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        self.validate_and_store_round_three_public(message)?;

        // If we have round three public values from all other participants, we
        // are done with the protocol! All we have left to do is create the
        // presign record.
        if self
            .local_storage
            .contains_for_all_ids::<storage::RoundThreePublic<C>>(&self.other_participant_ids)
        {
            let record = self.do_presign_finish()?;
            self.status = Status::TerminatedSuccessfully;
            Ok(ProcessOutcome::Terminated(record))
        } else {
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Finish the presign protocol.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn do_presign_finish(&mut self) -> Result<PresignRecord<C>> {
        info!("Doing presign finish. Creating presign record.");
        // Collect the other participants' round three public values from storage.
        let r3_pubs = self
            .other_participant_ids
            .iter()
            .map(|pid| {
                Ok(self
                    .local_storage
                    .retrieve::<storage::RoundThreePublic<C>>(*pid)?
                    .clone())
            })
            .collect::<Result<Vec<_>>>()?;

        let r3_private = self
            .local_storage
            .retrieve::<storage::RoundThreePrivate<C>>(self.id)?;

        // Check consistency across all Gamma values
        for (i, r3_pub) in r3_pubs.iter().enumerate() {
            if r3_pub.Gamma != r3_private.Gamma {
                error!(
                    "Mismatch in Gamma values for r3_private and the r3_pub of participant: {:?}",
                    &self.other_participant_ids[i]
                );
                return Err(InternalError::ProtocolError(None));
            }
        }

        // Note: This `try_into` call does the check and computation specified
        // in Step 2 of Output in the paper's protocol specification (Figure 7).
        let presign_record: PresignRecord<C> = RecordPair {
            private: r3_private.clone(),
            publics: r3_pubs,
        }
        .try_into()?;

        Ok(presign_record)
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn validate_and_store_round_two_public(&mut self, message: &Message) -> Result<()> {
        self.check_for_duplicate_msg::<storage::RoundTwoPublic<C>>(message.from())?;

        let input = self.input();

        let receiver_auxinfo_public = input.find_auxinfo_public(message.to())?;
        let sender_auxinfo_public = input.find_auxinfo_public(message.from())?;
        let sender_keyshare_public = input.find_keyshare_public(message.from())?;
        let receiver_r1_private = self
            .local_storage
            .retrieve::<storage::RoundOnePrivate>(message.to())?;
        let sender_r1_public_broadcast = self
            .local_storage
            .retrieve::<storage::RoundOnePublicBroadcast>(message.from())?;

        let round_two_public = round_two::Public::try_from(message)?;
        round_two_public.clone().verify(
            &self.retrieve_context().for_participant(message.from()),
            receiver_auxinfo_public,
            receiver_r1_private,
            sender_auxinfo_public,
            sender_keyshare_public,
            sender_r1_public_broadcast,
        )?;

        self.local_storage
            .store_once::<storage::RoundTwoPublic<C>>(message.from(), round_two_public)?;

        Ok(())
    }

    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn validate_and_store_round_three_public(&mut self, message: &Message) -> Result<()> {
        self.check_for_duplicate_msg::<storage::RoundThreePublic<C>>(message.from())?;

        let input = self.input();
        let receiver_auxinfo_public = input.find_auxinfo_public(message.to())?;
        let sender_auxinfo_public = input.find_auxinfo_public(message.from())?;
        let sender_r1_public_broadcast = self
            .local_storage
            .retrieve::<storage::RoundOnePublicBroadcast>(message.from())?;
        let public = round_three::Public::try_from(message)?;
        public.clone().verify(
            &self.retrieve_context().for_participant(message.from()),
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_r1_public_broadcast,
        )?;

        self.local_storage
            .store_once::<storage::RoundThreePublic<C>>(message.from(), public)?;
        Ok(())
    }
}

/// Convenience struct used to bundle together the parameters for
/// the current participant.
///
/// TODO: Refactor as specified in #246.
pub(crate) struct PresignKeyShareAndInfo<C> {
    pub(crate) keyshare_private: KeySharePrivate<C>,
    pub(crate) keyshare_public: KeySharePublic<C>,
    pub(crate) aux_info_private: AuxInfoPrivate,
    pub(crate) aux_info_public: AuxInfoPublic,
}

impl<C: CurveTrait> PresignKeyShareAndInfo<C> {
    fn new(id: ParticipantIdentifier, input: &Input<C>) -> Result<Self> {
        Ok(Self {
            aux_info_private: input.private_auxinfo().clone(),
            aux_info_public: input.find_auxinfo_public(id)?.clone(),
            keyshare_private: input.private_key_share().clone(),
            keyshare_public: input.find_keyshare_public(id)?.clone(),
        })
    }

    /// Round one of the presign protocol.
    ///
    /// This round produces two local shares `k` and `ɣ` along with their
    /// ciphertexts encrypted using this participant's Paillier encryption key,
    /// alongside a zero knowledge proof that the ciphertext associated with `k`
    /// was constructed correctly. We utilize the `other_auxinfos` argument to
    /// construct this proof, as it has to be tailored to the particular
    /// receiving participant.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn round_one<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        context: &ParticipantPresignContext<C>,
        other_auxinfos: &[&AuxInfoPublic],
    ) -> Result<(
        round_one::Private,
        HashMap<ParticipantIdentifier, round_one::Public<C>>,
        round_one::PublicBroadcast,
    )> {
        let order = C::order();

        let k = random_positive_bn(rng, &order);
        let gamma = random_positive_bn(rng, &order);

        let (K, rho) = self
            .aux_info_public
            .pk()
            .encrypt(rng, &k)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let (G, nu) = self
            .aux_info_public
            .pk()
            .encrypt(rng, &gamma)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let mut r1_publics = HashMap::new();
        let secret = PiEncSecret::new(&k, &rho);
        for aux_info_public in other_auxinfos {
            // Construct a proof that `K` is the ciphertext of `k` using
            // parameters from the other participant.
            let mut transcript = Transcript::new(b"PiEncProof");
            let proof = PiEncProof::prove(
                PiEncInput::new(aux_info_public.params(), self.aux_info_public.pk(), &K),
                secret,
                context,
                &mut transcript,
                rng,
            )?;
            let r1_public = round_one::Public::from(proof);
            let _ = r1_publics.insert(aux_info_public.participant(), r1_public);
        }

        let r1_public_broadcast = round_one::PublicBroadcast {
            K: K.clone(),
            G: G.clone(),
        };

        let r1_private = round_one::Private {
            k,
            rho,
            gamma,
            nu,
            G,
            K,
        };

        Ok((r1_private, r1_publics, r1_public_broadcast))
    }

    /// Round two of the presign protocol.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn round_two<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        context: &ParticipantPresignContext<C>,
        receiver_aux_info: &AuxInfoPublic,
        sender_r1_priv: &round_one::Private,
        receiver_r1_pub_broadcast: &round_one::PublicBroadcast,
    ) -> Result<(round_two::Private, round_two::Public<C>)> {
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
        let (beta_ciphertext, s) = receiver_aux_info
            .pk()
            .encrypt(rng, &beta)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let (beta_hat_ciphertext, s_hat) = receiver_aux_info
            .pk()
            .encrypt(rng, &beta_hat)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let D = receiver_aux_info
            .pk()
            .multiply_and_add(
                &sender_r1_priv.gamma,
                &receiver_r1_pub_broadcast.K,
                &beta_ciphertext,
            )
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let D_hat = receiver_aux_info
            .pk()
            .multiply_and_add(
                self.keyshare_private.as_ref(),
                &receiver_r1_pub_broadcast.K,
                &beta_hat_ciphertext,
            )
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let (F, r) = self
            .aux_info_public
            .pk()
            .encrypt(rng, &beta)
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let (F_hat, r_hat) = self
            .aux_info_public
            .pk()
            .encrypt(rng, &beta_hat)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let g = C::GENERATOR;
        let Gamma = g.mul_by_bn(&sender_r1_priv.gamma)?;

        // Generate the proofs.
        let mut transcript = Transcript::new(b"PiAffgProof");
        let secret = PiAffgSecret::new(&sender_r1_priv.gamma, &beta, &s, &r);
        let psi = PiAffgProof::prove(
            PiAffgInput::new(
                receiver_aux_info.params(),
                receiver_aux_info.pk(),
                self.aux_info_public.pk(),
                &receiver_r1_pub_broadcast.K,
                &D,
                &F,
                &Gamma,
            ),
            secret,
            context,
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiAffgProof");
        let secret = PiAffgSecret::new(self.keyshare_private.as_ref(), &beta_hat, &s_hat, &r_hat);
        let psi_hat = PiAffgProof::prove(
            PiAffgInput::new(
                receiver_aux_info.params(),
                receiver_aux_info.pk(),
                self.aux_info_public.pk(),
                &receiver_r1_pub_broadcast.K,
                &D_hat,
                &F_hat,
                self.keyshare_public.as_ref(),
            ),
            secret,
            context,
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiLogProof");
        let secret = ProverSecret::new(&sender_r1_priv.gamma, &sender_r1_priv.nu);
        let psi_prime = PiLogProof::prove(
            CommonInput::new(
                &sender_r1_priv.G,
                &Gamma,
                receiver_aux_info.params().scheme(),
                self.aux_info_public.pk(),
                &g,
            ),
            secret,
            context,
            &mut transcript,
            rng,
        )?;

        Ok((
            round_two::Private { beta, beta_hat },
            round_two::Public {
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

    /// Round three of the presign protocol.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[allow(clippy::type_complexity)]
    fn round_three<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        context: &ParticipantPresignContext<C>,
        sender_r1_priv: &round_one::Private,
        other_participant_inputs: &HashMap<ParticipantIdentifier, round_three::Input<C>>,
    ) -> Result<(
        round_three::Private<C>,
        HashMap<ParticipantIdentifier, round_three::Public<C>>,
    )> {
        let order = C::order();
        let g = C::GENERATOR;

        let mut delta: BigNumber = sender_r1_priv.gamma.modmul(&sender_r1_priv.k, &order);
        let mut chi: BigNumber = self
            .keyshare_private
            .as_ref()
            .modmul(&sender_r1_priv.k, &order);
        let mut Gamma = g.mul_by_bn(&sender_r1_priv.gamma)?;

        for round_three_input in other_participant_inputs.values() {
            let r2_pub_j = round_three_input.r2_public.clone();
            let r2_priv_j = round_three_input.r2_private.clone();

            let alpha = self
                .aux_info_private
                .decryption_key()
                .decrypt(&r2_pub_j.D)
                .map_err(|_| {
                    error!(
                        "Decryption failed, ciphertext out of range: {:?}",
                        r2_pub_j.D
                    );
                    InternalError::ProtocolError(None)
                })?;
            let alpha_hat = self
                .aux_info_private
                .decryption_key()
                .decrypt(&r2_pub_j.D_hat)
                .map_err(|_| {
                    error!(
                        "Decryption failed, ciphertext out of range: {:?}",
                        r2_pub_j.D_hat
                    );
                    InternalError::ProtocolError(None)
                })?;

            // Note: We do a subtraction of `beta` and `beta_hat` here because
            // in round two we did _not_ encrypt the negation of these as
            // specified in the protocol. See comment in `round_two` for the
            // reasoning.
            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);
            Gamma = Gamma + r2_pub_j.Gamma;
        }

        let Delta = Gamma.mul_by_bn(&sender_r1_priv.k)?;

        let delta_scalar = C::bn_to_scalar(&delta)?;
        let chi_scalar = C::bn_to_scalar(&chi)?;

        let mut ret_publics = HashMap::new();
        for (other_id, round_three_input) in other_participant_inputs {
            let mut transcript = Transcript::new(b"PiLogProof");
            let psi_double_prime = PiLogProof::prove(
                CommonInput::new(
                    &sender_r1_priv.K,
                    &Delta,
                    round_three_input.auxinfo_public.params().scheme(),
                    self.aux_info_public.pk(),
                    &Gamma,
                ),
                ProverSecret::new(&sender_r1_priv.k, &sender_r1_priv.rho),
                context,
                &mut transcript,
                rng,
            )?;
            let val = round_three::Public {
                delta: delta_scalar,
                Delta,
                psi_double_prime,
                Gamma,
            };
            let _ = ret_publics.insert(*other_id, val);
        }

        let private = round_three::Private {
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

use crate::participant::Status;
#[cfg(test)]
pub(super) use test::presign_record_set_is_valid;

#[cfg(test)]
mod test {
    use std::{collections::HashMap, iter::zip};

    use libpaillier::unknown_order::BigNumber;
    use rand::{CryptoRng, Rng, RngCore};
    use tracing::debug;

    use crate::{
        auxinfo,
        curve::{CurveTrait, ScalarTrait, TestCurve},
        errors::Result,
        keygen,
        messages::{Message, MessageType, PresignMessageType},
        participant::{ProcessOutcome, Status},
        presign::{self, Input},
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ParticipantIdentifier, ProtocolParticipant,
    };
    type PresignRecord = presign::PresignRecord<TestCurve>;

    use super::PresignParticipant;

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

    #[allow(clippy::type_complexity)]
    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut [PresignParticipant<TestCurve>],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
    ) -> Option<(usize, ProcessOutcome<PresignRecord>)> {
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

    pub(crate) fn presign_record_set_is_valid(
        records: Vec<PresignRecord>,
        keygen_outputs: Vec<keygen::Output<TestCurve>>,
    ) {
        // Every presign record has the same `R` value
        // We don't stick this in a HashSet because `CurvePoint`s can't be hashed :(
        assert!(records
            .windows(2)
            .all(|records| records[0].mask_point() == records[1].mask_point()));
        let mask_point = records[0].mask_point();

        // Mask point `R` is correctly formed with respect to the mask `k`:
        // `R = g^(k^-1)`, where `g` is the generator of the elliptic curve
        // and `k` is the sum of the mask shares `k_i` in all the presign records
        let mask = records.iter().map(|record| record.mask_share()).fold(
            <TestCurve as CurveTrait>::Scalar::zero(),
            |sum, mask_share| sum + mask_share,
        );
        let inverse: <TestCurve as CurveTrait>::Scalar = Option::from(mask.invert()).unwrap();
        assert_eq!(
            mask_point,
            &TestCurve::GENERATOR.multiply_by_scalar(&inverse)
        );

        // The masked key `Chi` is correctly formed with respect to the mask `k` and
        // secret key `x`: `Chi = x * k (mod q)`
        let masked_key = records.iter().map(|record| record.masked_key_share()).fold(
            <TestCurve as CurveTrait>::Scalar::ZERO,
            |sum, masked_key_share| sum + masked_key_share,
        );
        let secret_key = keygen_outputs
            .iter()
            .map(|output| output.private_key_share())
            .fold(BigNumber::zero(), |sum, key_share| sum + key_share.as_ref());
        // Converting to scalars automatically gets us the mod q
        assert_eq!(
            masked_key,
            TestCurve::bn_to_scalar(&secret_key).unwrap() * mask,
        );
    }

    #[test]
    fn presign_produces_valid_outputs() -> Result<()> {
        let quorum_size = 4;
        let rng = &mut init_testing();

        // Prepare prereqs for making PresignParticipants. Assume all the simulations
        // are stable (e.g. keep config order)
        let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
        let keygen_outputs = keygen::Output::simulate_set(&configs, rng);
        let auxinfo_outputs = auxinfo::Output::simulate_set(&configs, rng);

        let sid = Identifier::random(rng);

        // Make the participants
        let mut quorum = zip(configs, zip(keygen_outputs.clone(), auxinfo_outputs))
            .map(|(config, (keygen_output, auxinfo_output))| {
                let input = Input::new(auxinfo_output, keygen_output)?;
                PresignParticipant::new(sid, config.id(), config.other_ids().to_vec(), input)
            })
            .collect::<Result<Vec<_>>>()?;

        // Make inboxes for message passing
        let mut inboxes = HashMap::new();
        for participant in &quorum {
            let _ = inboxes.insert(participant.id, vec![]);
        }

        // Make a place to store outputs
        let mut outputs = std::iter::repeat_with(|| None)
            .take(quorum_size)
            .collect::<Vec<_>>();

        // Pass everyone a ready message
        for (pid, inbox) in &mut inboxes {
            let empty: [u8; 0] = [];
            inbox.push(Message::new(
                MessageType::Presign(PresignMessageType::Ready),
                sid,
                *pid,
                *pid,
                &empty,
            )?);
        }

        // Run protocol until all participants report that they're done
        while !quorum
            .iter()
            .all(|participant| *participant.status() == Status::TerminatedSuccessfully)
        {
            let (index, outcome) = match process_messages(&mut quorum, &mut inboxes, rng) {
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

        // Get rid of any `None` outputs
        let records = outputs.into_iter().flatten().collect::<Vec<_>>();

        // Every party must produce an output
        assert_eq!(records.len(), quorum_size);

        // Check validity of set; this will panic if anything is wrong
        presign_record_set_is_valid(records, keygen_outputs);

        Ok(())
    }
}
