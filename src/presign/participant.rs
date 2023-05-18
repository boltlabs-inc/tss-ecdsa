//! Types and functions related to the pre-signing sub-protocol Participant.

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
    errors::{CallerError, InternalError, Result},
    keygen::{self, KeySharePrivate, KeySharePublic},
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
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    run_only_once,
    utils::{bn_to_scalar, k256_order, random_plusminus_by_size, random_positive_bn, CurvePoint},
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
    use crate::local_storage::TypeTag;

    pub(super) struct Ready;
    impl TypeTag for Ready {
        type Value = ();
    }
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
    /// Participant has been initialized.
    Initialized,
    /// Participant has finished the sub-protocol.
    TerminatedSuccessfully,
}

/// This type includes relevant context for transcripts produced in `presign`,
/// and includes [`SharedContext`] and [`AuxInfoPublic`]s for all participants
/// (including this participant).
#[derive(Debug)]
pub(crate) struct PresignContext {
    shared_context: SharedContext,
    auxinfo_public: Vec<AuxInfoPublic>,
}

impl ProofContext for PresignContext {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok([
            self.shared_context.as_bytes()?,
            bincode::serialize(&self.auxinfo_public)
                .map_err(|_| InternalError::InternalInvariantFailed)?,
        ]
        .concat())
    }
}

impl PresignContext {
    /// Build a [`PresignContext`] from a [`PresignParticipant`].
    pub(crate) fn collect(p: &PresignParticipant) -> Self {
        let mut auxinfo_public = p.input().all_auxinfo_public();
        auxinfo_public.sort_by_key(AuxInfoPublic::participant);
        Self {
            shared_context: SharedContext::collect(p),
            auxinfo_public,
        }
    }
}

/// A [`ProtocolParticipant`] that runs the presign protocol[^cite].
///
/// # Protocol input
/// The protocol takes an [`Input`] which includes:
/// - The [`Output`](keygen::Output) of a [`keygen`] protocol execution
///   - A list of public key shares, one for each participant (including this
///     participant);
///   - A single private key share for this participant; and
///   - A random value, agreed on by all participants.
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
/// # High-level protocol description
/// The goal of the presign protocol is to generate [`PresignRecord`]s for all
/// protocol participants. The protocol proceeds in four rounds, and utilizes
/// the [`KeySharePrivate`] (`xᵢ` in the paper) constructed during the
/// [`keygen`](crate::keygen::KeygenParticipant) protocol.
///
/// 1. In round one, each participant generates two values corresponding to a
///    "key share" (`kᵢ` in the paper) and an "exponent share" (`ɣᵢ` in the
///    paper). At the end of a successful run of the protocol, each participant
///    constructs a value equal to `(∑ kᵢ) (∑ ɣᵢ)`, which is used to generate
///    the [`PresignRecord`].
///
///    The participant then encrypts these values and constructs a
///    zero-knowledge proof that the ciphertext (`Kᵢ` in the paper)
///    corresponding to its key share `kᵢ` was encrypted correctly. This proof
///    needs to be done once per-participant (that is, if there are `n` total
///    participants then each participant generates `n-1` such proofs, one for
///    each other participant).
///
/// 2. Once each participant has received these values and proofs from all other
///    participants, it verifies the proofs. If those all pass, it proceeds to
///    round two. In this round, each participant `i`, for each other
///    participant `j`, creates the following values:
///
///    - An exponentiation of its exponent share: `Γᵢ = g^{ɣᵢ}`.
///    - A "mask" of its exponent share, roughly equal to `(ɣᵢ · Kⱼ)`.
///    - A "mask" of its [`KeySharePrivate`], roughly equal to `(xᵢ · Kⱼ)`.
///
///    It also attaches relevant zero-knowledge proofs (per participant) that
///    the above computations were done correctly.
///
/// 3. Once each participant has received these values and proofs from all other
///    participants, it verifies the proofs. If those all pass, it proceeds to
///    round three. In this round, each participant creates the following
///    values:
///
///    - A multiplication of all the exponentiated exponent shares: `Γ = ∏ᵢ Γᵢ =
///      g^{∑ ɣᵢ}`.
///    - An exponentiation of its key share by this new value: `Δᵢ = Γ^{kᵢ} =
///      g^{kᵢ ∑ ɣᵢ}`.
///    - An "unmasked" exponent share summation multiplied by its own key share:
///      `δᵢ = (∑ ɣⱼ) kᵢ`.
///    - An "unmasked" [`KeySharePrivate`] summation multiplied by its own key
///      share: `χᵢ = (∑ xⱼ) kᵢ`.
///
///    It also attaches a zero-knowledge proof (per participant) that the value
///    `Δᵢ` was computed correctly.
///
/// 4. Once each participant has received these values and proofs from all other
///    participants, it verifies the proofs. If those all pass, it proceeds to
///    round four. In this round, each participant combines the `δᵢ` values and
///    checks that `g^{∑ δᵢ} = ∏ᵢ Δᵢ`, which essentially checks that the value
///    `g^{ɣ k}` was computed correctly, where `ɣ = ∑ ɣᵢ` and `k = ∑ kᵢ`.
///    (Recall that `g^{ɣ k}` was the value we were aiming to compute in the
///    first place.)
///
///    If this holds, each participant can output its [`PresignRecord`] as the
///    tuple `(Γ^{(ɣ k)^{-1}}, kᵢ, χᵢ)`.
///
/// [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
/// Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
/// with Identifiable Aborts. [EPrint archive,
/// 2021](https://eprint.iacr.org/2021/060.pdf). Figure 7.
#[derive(Debug)]
pub struct PresignParticipant {
    /// The current session identifier.
    sid: Identifier,
    /// The current protocol input.
    input: Input,
    /// A unique identifier for this participant.
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol.
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets.
    local_storage: LocalStorage,
    /// Broadcast subprotocol handler.
    broadcast_participant: BroadcastParticipant,
    /// Status of the protocol execution.
    status: Status,
}

/// Input needed for [`PresignParticipant`] to run.
#[derive(Debug, Clone)]
pub struct Input {
    /// The key share material for the key corresponding to the presign run.
    keygen_output: keygen::Output,
    /// The private auxinfo of this participant.
    auxinfo_private: AuxInfoPrivate,
    /// The public auxinfo of all the participants (including this participant).
    all_auxinfo_public: Vec<AuxInfoPublic>,
}

impl Input {
    /// Creates a new [`Input`] from the outputs of the
    /// [`auxinfo`](crate::auxinfo::participant::AuxInfoParticipant) and
    /// [`keygen`](crate::keygen::KeygenParticipant) protocols.
    pub fn new(
        all_auxinfo_public: Vec<AuxInfoPublic>,
        auxinfo_private: AuxInfoPrivate,
        keygen_output: keygen::Output,
    ) -> Result<Self> {
        if all_auxinfo_public.len() != keygen_output.public_key_shares().len() {
            error!(
                "Number of auxinfo ({:?}) and keyshare ({:?}) public entries is not equal",
                all_auxinfo_public.len(),
                keygen_output.public_key_shares().len()
            );
            Err(CallerError::BadInput)?
        }

        // The same set of participants must have produced the key shares and aux infos.
        let aux_sids = all_auxinfo_public
            .iter()
            .map(|auxinfo| auxinfo.participant())
            .collect::<HashSet<_>>();
        let key_sids = keygen_output
            .public_key_shares()
            .iter()
            .map(|keyshare| keyshare.participant())
            .collect::<HashSet<_>>();
        if aux_sids != key_sids {
            error!("Public auxinfo and keyshare inputs to presign weren't from the same set of parties.");
            Err(CallerError::BadInput)?
        }

        // There shouldn't be duplicates. Since we checked equality of the sets and the
        // lengths already, this also applies to auxinfo.
        if key_sids.len() != keygen_output.public_key_shares().len() {
            error!("Duplicate participant IDs appeared in AuxInfo and KeyShare public input.");
            Err(CallerError::BadInput)?
        }

        // The private values should map to one of the public values.
        let expected_public_share = keygen_output.private_key_share().public_share()?;
        if !keygen_output
            .public_key_shares()
            .iter()
            .any(|public_share| expected_public_share == *public_share.as_ref())
        {
            error!("Keygen private share did not correspond to any of the provided keygen public shares.");
            Err(CallerError::BadInput)?
        }
        if !all_auxinfo_public
            .iter()
            .any(|auxinfo| &auxinfo_private.encryption_key() == auxinfo.pk())
        {
            error!("Auxinfo private key did not match any of the provided auxinfo public keys.");
            Err(CallerError::BadInput)?
        }

        Ok(Self {
            all_auxinfo_public,
            auxinfo_private,
            keygen_output,
        })
    }

    /// Get the set of participants that contributed to the input.
    ///
    /// By construction, this must be the same for the auxinfo and key share
    /// lists.
    fn participants(&self) -> Vec<ParticipantIdentifier> {
        self.keygen_output
            .public_key_shares()
            .iter()
            .map(KeySharePublic::participant)
            .collect()
    }

    /// Returns the [`AuxInfoPublic`] associated with the given
    /// [`ParticipantIdentifier`].
    fn find_auxinfo_public(&self, pid: ParticipantIdentifier) -> Result<&AuxInfoPublic> {
        self.all_auxinfo_public
            .iter()
            .find(|item| item.participant() == pid)
            .ok_or_else(|| {
                error!("Presign input doesn't contain a public auxinfo for {}, even though we checked for it at construction.", pid);
                InternalError::InternalInvariantFailed
            })
    }

    /// Returns the [`KeySharePublic`] associated with the given
    /// [`ParticipantIdentifier`].
    fn find_keyshare_public(&self, pid: ParticipantIdentifier) -> Result<&KeySharePublic> {
        self.keygen_output
            .public_key_shares()
            .iter()
            .find(|item| item.participant() == pid)
            .ok_or_else(|| {
                error!("Presign input doesn't contain a public keyshare for {}, even though we checked for it at construction.", pid);
                InternalError::InternalInvariantFailed
            })
    }

    /// Returns the [`AuxInfoPublic`]s associated with all the participants
    /// _except_ the given [`ParticipantIdentifier`].
    fn all_but_one_auxinfo_public(&self, pid: ParticipantIdentifier) -> Vec<&AuxInfoPublic> {
        self.all_auxinfo_public
            .iter()
            .filter(|item| item.participant() != pid)
            .collect()
    }
    /// Returns a copy of the [`AuxInfoPublic`]s associated with all the
    /// participants (including this participant).
    fn all_auxinfo_public(&self) -> Vec<AuxInfoPublic> {
        self.all_auxinfo_public.clone()
    }
}

impl ProtocolParticipant for PresignParticipant {
    type Input = Input;
    type Output = PresignRecord;
    type Status = Status;

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
            status: Status::Initialized,
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

    fn input(&self) -> &Self::Input {
        &self.input
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
        input: &Self::Input,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing presign message.");

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
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
                self.handle_round_three_msg(message, input)
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

    fn status(&self) -> &Self::Status {
        &self.status
    }
}

impl InnerProtocolParticipant for PresignParticipant {
    type Context = PresignContext;

    fn retrieve_context(&self) -> <Self as InnerProtocolParticipant>::Context {
        PresignContext::collect(self)
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
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling ready presign message.");

        let (ready_outcome, is_ready) = self.process_ready_message::<storage::Ready>(message)?;

        if is_ready {
            let round_one_messages =
                run_only_once!(self.gen_round_one_msgs(rng, message.id(), input))?;
            Ok(ready_outcome.with_messages(round_one_messages))
        } else {
            Ok(ready_outcome)
        }
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
        input: &Input,
    ) -> Result<Vec<Message>> {
        info!("Generating round one presign messages.");

        let info = PresignKeyShareAndInfo::new(self.id, input)?;
        let other_public_auxinfo = input.all_but_one_auxinfo_public(self.id);

        // Run round one.
        let (private, r1_publics, r1_public_broadcast) =
            info.round_one(rng, &self.retrieve_context(), &other_public_auxinfo)?;

        // Store private round one value locally.
        self.local_storage
            .store::<storage::RoundOnePrivate>(self.id, private);

        // Generate round one messages for all other participants.
        let mut messages = r1_publics
            .into_iter()
            .map(|(other_id, r1_public)| {
                Ok(Message::new(
                    MessageType::Presign(PresignMessageType::RoundOne),
                    sid,
                    self.id,
                    other_id,
                    &serialize!(&r1_public)?,
                ))
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
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Presign: Handling round one broadcast message.");

        let message = broadcast_message.into_message(BroadcastTag::PresignR1Ciphertexts)?;
        let public_broadcast: RoundOnePublicBroadcast = deserialize!(&message.unverified_bytes)?;
        self.local_storage
            .store::<storage::RoundOnePublicBroadcast>(message.from(), public_broadcast);

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
            return Err(InternalError::ProtocolError);
        }
        match retrieved_messages.get(0) {
            Some(message) => self.handle_round_one_msg(rng, message, input),
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
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        use crate::round_one::Public as RoundOnePublic;

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

        let info = PresignKeyShareAndInfo::new(self.id, input)?;
        let auxinfo_public = input.find_auxinfo_public(message.from())?;
        let round_one_public = RoundOnePublic::try_from(message)?;
        round_one_public.verify(
            &self.retrieve_context(),
            info.aux_info_public.params(),
            auxinfo_public.pk(),
            r1_public_broadcast,
        )?;
        // Mark that we have completed round one for this participant.
        //
        // Since we don't need the round one message in the rest of the
        // protocol, we don't need to store it in storage.
        self.local_storage
            .store::<storage::RoundOneComplete>(message.from(), ());
        // Check if we're done with round one by checking that we're done with
        // round one for all other participants.
        if self
            .local_storage
            .contains_for_all_ids::<storage::RoundOneComplete>(&self.other_participant_ids)
        {
            info!("Presign: Round one complete. Generating round two messages.");
            // Finish round one by generating messages for round two.
            let round_two_messages =
                run_only_once!(self.gen_round_two_msgs(rng, message.id(), input))?;
            // Process any round two messages we may have received early.
            let round_two_outcomes = self
                .fetch_messages(MessageType::Presign(PresignMessageType::RoundTwo))?
                .iter()
                .map(|msg| self.handle_round_two_msg(rng, msg, input))
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
        input: &Input,
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
            let more_messages = run_only_once!(self.gen_round_one_msgs(rng, sid, input))?;
            messages.extend_from_slice(&more_messages);
        }

        let info = PresignKeyShareAndInfo::new(self.id, input)?;
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
                let sender_auxinfo_public = input.find_auxinfo_public(pid)?;
                let (r2_priv, r2_pub) = info.round_two(
                    rng,
                    &self.retrieve_context(),
                    sender_auxinfo_public,
                    r1_priv,
                    r1_public_broadcast,
                )?;
                self.local_storage
                    .store::<storage::RoundTwoPrivate>(pid, r2_priv);
                Ok(Message::new(
                    MessageType::Presign(PresignMessageType::RoundTwo),
                    sid,
                    self.id,
                    pid,
                    &serialize!(&r2_pub)?,
                ))
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
        input: &Input,
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

        self.validate_and_store_round_two_public(input, message)?;

        // Check if storage has all of the other participants' round two values
        // (both private and public), and start generating the messages for
        // round three if so.
        let all_privates_received = self
            .local_storage
            .contains_for_all_ids::<storage::RoundTwoPrivate>(&self.other_participant_ids);
        let all_publics_received = self
            .local_storage
            .contains_for_all_ids::<storage::RoundTwoPublic>(&self.other_participant_ids);
        if all_privates_received && all_publics_received {
            info!("Presign: Round two complete. Generating round three messages.");
            // Generate messages for round three...
            let messages = run_only_once!(self.gen_round_three_msgs(rng, message.id(), input))?;
            // ... and handle any messages that other participants have sent for round
            // three.
            let outcomes = self
                .fetch_messages(MessageType::Presign(PresignMessageType::RoundThree))?
                .iter()
                .map(|msg| self.handle_round_three_msg(msg, input))
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
        input: &Input,
    ) -> Result<Vec<Message>> {
        info!("Generating round three presign messages.");

        let info = PresignKeyShareAndInfo::new(self.id, input)?;
        // Collect the other participant's values from storage needed for round
        // three.
        let mut hashmap = HashMap::new();
        for pid in self.other_participant_ids.clone() {
            let auxinfo_public = input.find_auxinfo_public(pid)?;
            let r2_private = self
                .local_storage
                .retrieve::<storage::RoundTwoPrivate>(pid)?;
            let r2_public = self
                .local_storage
                .retrieve::<storage::RoundTwoPublic>(pid)?;
            let _ = hashmap.insert(
                pid,
                RoundThreeInput {
                    auxinfo_public: auxinfo_public.clone(),
                    r2_private: r2_private.clone(),
                    r2_public: r2_public.clone(),
                },
            );
        }

        let r1_priv = self
            .local_storage
            .retrieve::<storage::RoundOnePrivate>(self.id)?;

        let (r3_private, r3_publics_map) =
            info.round_three(rng, &self.retrieve_context(), r1_priv, &hashmap)?;

        self.local_storage
            .store::<storage::RoundThreePrivate>(self.id, r3_private);

        let messages = r3_publics_map
            .into_iter()
            .map(|(id, r3_public)| {
                Ok(Message::new(
                    MessageType::Presign(PresignMessageType::RoundThree),
                    sid,
                    self.id,
                    id,
                    &serialize!(&r3_public)?,
                ))
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
        input: &Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round three presign message.");

        // If we have not yet started round three, stash the message for later.
        // We check that we've started round three by checking whether our own
        // private round three value exists in storage.
        if !self
            .local_storage
            .contains::<storage::RoundThreePrivate>(self.id)
        {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        self.validate_and_store_round_three_public(input, message)?;

        // If we have round three public values from all other participants, we
        // are done with the protocol! All we have left to do is create the
        // presign record.
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

    /// Finish the presign protocol.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    #[instrument(skip_all, err(Debug))]
    fn do_presign_finish(&mut self) -> Result<PresignRecord> {
        info!("Doing presign finish. Creating presign record.");
        // Collect the other participants' round three public values from storage.
        let r3_pubs = self
            .other_participant_ids
            .iter()
            .map(|pid| {
                Ok(self
                    .local_storage
                    .retrieve::<storage::RoundThreePublic>(*pid)?
                    .clone())
            })
            .collect::<Result<Vec<_>>>()?;

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

        // Note: This `try_into` call does the check and computation specified
        // in Step 2 of Output in the paper's protocol specification (Figure 7).
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

        let round_two_public = RoundTwoPublic::try_from(message)?;
        round_two_public.verify(
            &self.retrieve_context(),
            receiver_auxinfo_public,
            receiver_r1_private,
            sender_auxinfo_public,
            sender_keyshare_public,
            sender_r1_public_broadcast,
        )?;

        self.local_storage
            .store::<storage::RoundTwoPublic>(message.from(), round_two_public);

        Ok(())
    }

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
        let public = RoundThreePublic::try_from(message)?;
        public.verify(
            &self.retrieve_context(),
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_r1_public_broadcast,
        )?;

        self.local_storage
            .store::<storage::RoundThreePublic>(message.from(), public);
        Ok(())
    }
}

/// Convenience struct used to bundle together the parameters for
/// the current participant.
///
/// TODO: Refactor as specified in #246.
pub(crate) struct PresignKeyShareAndInfo {
    pub(crate) keyshare_private: KeySharePrivate,
    pub(crate) keyshare_public: KeySharePublic,
    pub(crate) aux_info_private: AuxInfoPrivate,
    pub(crate) aux_info_public: AuxInfoPublic,
}

impl PresignKeyShareAndInfo {
    fn new(id: ParticipantIdentifier, input: &Input) -> Result<Self> {
        Ok(Self {
            aux_info_private: input.auxinfo_private.clone(),
            aux_info_public: input.find_auxinfo_public(id)?.clone(),
            keyshare_private: input.keygen_output.private_key_share().clone(),
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
        context: &impl ProofContext,
        other_auxinfos: &[&AuxInfoPublic],
    ) -> Result<(
        RoundOnePrivate,
        HashMap<ParticipantIdentifier, RoundOnePublic>,
        RoundOnePublicBroadcast,
    )> {
        let order = k256_order();

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
        let secret = PiEncSecret::new(k.clone(), rho.clone());
        for aux_info_public in other_auxinfos {
            // Construct a proof that `K` is the ciphertext of `k` using
            // parameters from the other participant.
            let mut transcript = Transcript::new(b"PiEncProof");
            let proof = PiEncProof::prove(
                &PiEncInput::new(
                    aux_info_public.params().clone(),
                    self.aux_info_public.pk().clone(),
                    K.clone(),
                ),
                &secret,
                context,
                &mut transcript,
                rng,
            )?;
            let r1_public = RoundOnePublic::from(proof);
            let _ = r1_publics.insert(aux_info_public.participant(), r1_public);
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

    /// Round two of the presign protocol.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn round_two<R: RngCore + CryptoRng>(
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

        let g = CurvePoint::GENERATOR;
        let Gamma = g.multiply_by_scalar(&sender_r1_priv.gamma)?;

        // Generate the proofs.
        let mut transcript = Transcript::new(b"PiAffgProof");
        let secret = PiAffgSecret::new(sender_r1_priv.gamma.clone(), beta.clone(), s, r);
        let psi = PiAffgProof::prove(
            &PiAffgInput::new(
                receiver_aux_info.params().clone(),
                receiver_aux_info.pk().clone(),
                self.aux_info_public.pk().clone(),
                receiver_r1_pub_broadcast.K.clone(),
                D.clone(),
                F.clone(),
                Gamma,
            ),
            &secret,
            context,
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiAffgProof");
        let secret = PiAffgSecret::new(
            self.keyshare_private.as_ref().clone(),
            beta_hat.clone(),
            s_hat,
            r_hat,
        );
        let psi_hat = PiAffgProof::prove(
            &PiAffgInput::new(
                receiver_aux_info.params().clone(),
                receiver_aux_info.pk().clone(),
                self.aux_info_public.pk().clone(),
                receiver_r1_pub_broadcast.K.clone(),
                D_hat.clone(),
                F_hat.clone(),
                *self.keyshare_public.as_ref(),
            ),
            &secret,
            context,
            &mut transcript,
            rng,
        )?;
        let mut transcript = Transcript::new(b"PiLogProof");
        let secret = ProverSecret::new(sender_r1_priv.gamma.clone(), sender_r1_priv.nu.clone());
        let psi_prime = PiLogProof::prove(
            &CommonInput::new(
                sender_r1_priv.G.clone(),
                Gamma,
                receiver_aux_info.params().scheme().clone(),
                self.aux_info_public.pk().clone(),
                g,
            ),
            &secret,
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

    /// Round three of the presign protocol.
    #[cfg_attr(feature = "flame_it", flame("presign"))]
    fn round_three<R: RngCore + CryptoRng>(
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
        let g = CurvePoint::GENERATOR;

        let mut delta: BigNumber = sender_r1_priv.gamma.modmul(&sender_r1_priv.k, &order);
        let mut chi: BigNumber = self
            .keyshare_private
            .as_ref()
            .modmul(&sender_r1_priv.k, &order);
        let mut Gamma = g.multiply_by_scalar(&sender_r1_priv.gamma)?;

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
                    InternalError::ProtocolError
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
                    InternalError::ProtocolError
                })?;

            // Note: We do a subtraction of `beta` and `beta_hat` here because
            // in round two we did _not_ encrypt the negation of these as
            // specified in the protocol. See comment in `round_two` for the
            // reasoning.
            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);
            Gamma = CurvePoint(Gamma.0 + r2_pub_j.Gamma.0);
        }

        let Delta = Gamma.multiply_by_scalar(&sender_r1_priv.k)?;

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

#[cfg(test)]
mod test {
    use rand::rngs::StdRng;

    use super::Input;
    use crate::{
        errors::{CallerError, InternalError, Result},
        keygen,
        paillier::DecryptionKey,
        ring_pedersen::VerifiedRingPedersen,
        utils::testing::init_testing,
        AuxInfoPrivate, AuxInfoPublic, Identifier, ParticipantConfig, ParticipantIdentifier,
        PresignParticipant, ProtocolParticipant,
    };
    // Simulate the output of an auxinfo run with the given participants.
    fn simulate_auxinfo_output(
        pids: &[ParticipantIdentifier],
        rng: &mut StdRng,
    ) -> (AuxInfoPrivate, Vec<AuxInfoPublic>) {
        let (mut auxinfo_private_outputs, auxinfo_public_outputs): (Vec<_>, Vec<_>) = pids
            .iter()
            .map(|&pid| {
                let (key, _, _) = DecryptionKey::new(rng).unwrap();
                (
                    AuxInfoPrivate::from(key.clone()),
                    AuxInfoPublic::new(
                        &(),
                        pid,
                        key.encryption_key(),
                        VerifiedRingPedersen::extract(&key, &(), rng).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .unzip();

        (
            auxinfo_private_outputs.pop().unwrap(),
            auxinfo_public_outputs,
        )
    }

    #[test]
    fn inputs_must_be_same_length() {
        let rng = &mut init_testing();

        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let keygen_output = keygen::Output::simulate(&pids, rng);
        let (auxinfo_private, auxinfo_public) = simulate_auxinfo_output(&pids, rng);

        // Same length works
        let result = Input::new(
            auxinfo_public.clone(),
            auxinfo_private.clone(),
            keygen_output.clone(),
        );
        assert!(result.is_ok());

        // If keygen is too short, it fails.
        let short_keygen = keygen::Output::simulate(&pids[1..], rng);
        let result = Input::new(
            auxinfo_public.clone(),
            auxinfo_private.clone(),
            short_keygen,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );

        // If auxinfo is too short, it fails.
        let mut short_auxinfo = auxinfo_public;
        let _dropped = short_auxinfo.pop();
        let result = Input::new(short_auxinfo, auxinfo_private, keygen_output);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );
    }

    #[test]
    fn inputs_must_not_have_duplicates() {
        let rng = &mut init_testing();

        let mut pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let (auxinfo_private, mut auxinfo_public) = simulate_auxinfo_output(&pids, rng);

        // This test doesn't bother adding a duplicate in only one of the inputs because
        // that would fail the length checks tested in `inputs_must_be_same_length`

        // Push a copy of one of the auxinfo publics.
        let auxinfo_dup = auxinfo_public.pop().unwrap();
        auxinfo_public.push(auxinfo_dup.clone());
        auxinfo_public.push(auxinfo_dup);

        // Make a keygen output with a duplicated pid (the public key material itself
        // will be different)
        pids.push(pids[4]); // take the last item to match the pop'd auxinfo pid.
        let keygen_output = keygen::Output::simulate(&pids, rng);

        let result = Input::new(auxinfo_public, auxinfo_private, keygen_output);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );
    }

    #[test]
    fn inputs_must_have_same_participant_sets() {
        let rng = &mut init_testing();

        let auxinfo_pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let (auxinfo_private, auxinfo_public) = simulate_auxinfo_output(&auxinfo_pids, rng);

        let keygen_pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let keygen_output = keygen::Output::simulate(&keygen_pids, rng);

        let result = Input::new(auxinfo_public, auxinfo_private, keygen_output);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );
    }

    #[test]
    fn inputs_must_have_a_public_private_pair() {
        let rng = &mut init_testing();

        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();

        let keygen_output = keygen::Output::simulate(&pids, rng);
        let (_, auxinfo_public) = simulate_auxinfo_output(&pids, rng);

        // Make a private auxinfo component with no relation to the public inputs.
        let fake_auxinfo_private = AuxInfoPrivate::from(DecryptionKey::new(rng).unwrap().0);

        // Auxinfo private key must correspond to one of the public inputs.
        let result = Input::new(auxinfo_public, fake_auxinfo_private, keygen_output);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );

        // Note: we can't test the same thing for keygen because the keygen
        // output type doesn't let us muck around with its internal
        // representation here. TODO #376: Add the equivalent test in
        // the keygen module.
    }

    #[test]
    fn protocol_participants_must_match_input_participants() -> Result<()> {
        let rng = &mut init_testing();
        let SIZE = 5;

        // Create valid input set with random PIDs
        let input_pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(SIZE)
            .collect::<Vec<_>>();
        let keygen_output = keygen::Output::simulate(&input_pids, rng);
        let (auxinfo_private, auxinfo_public) = simulate_auxinfo_output(&input_pids, rng);

        let input = Input::new(auxinfo_public, auxinfo_private, keygen_output)?;

        // Create valid config with PIDs independent of those used to make the input set
        let config = ParticipantConfig::random(SIZE, rng);

        let result =
            PresignParticipant::new(Identifier::random(rng), config.id, config.other_ids, input);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );

        Ok(())
    }
}
