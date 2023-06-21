// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The primary public API for executing the threshold signing protocol.
//!
//! This module includes the main [`Participant`] driver.

use crate::{
    errors::{CallerError, InternalError, Result},
    messages::{Message, MessageType},
    participant::{InnerProtocolParticipant, ProtocolParticipant},
    protocol::participant_config::ParticipantConfig,
    utils::{k256_order, CurvePoint},
    zkp::ProofContext,
};
use k256::elliptic_curve::IsHigh;
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    cmp::{Ord, PartialOrd},
    collections::HashSet,
    fmt::{Debug, Formatter},
};
use tracing::{error, info, instrument, trace};

/// The set of subprotocols that a [`Participant`] can execute.
///
/// Note: An external user will never explicitly instantiate a `Broadcast`
/// participant; this type is created internally to the library.
#[derive(Debug)]
pub enum ProtocolType {
    Keygen,
    AuxInfo,
    Presign,
    Broadcast,
}

/// The driver for a party executing a sub-protocol of the threshold signing
/// protocol.
///
/// A given [`Participant`] participates in an execution of one of several
/// sub-protocols required for threshold signing. The core functionality of
/// [`Participant`] is captured in the
/// [`process_single_message`](Participant::process_single_message) method: it
/// takes as input a [`Message`] and outputs a tuple containing the
/// participant's output alongside a list of messages to process.
///
/// # 🔒 Message handling
/// The calling application is responsible for receiving, sending and routing
/// all messages generated by participants of a sub-protocol session.
/// for its [`Participant`]. This includes:
/// 1. Initializing a session by calling [`Participant::initialize_message()`].
///    The message returned from that function must be passed back to the
/// [`Participant`] in order to begin the protocol execution.
/// 2. Receiving messages sent by other participants, and passing
/// them to the participant by calling
/// [`Participant::process_single_message()`]. 3. Sending all messages generated
/// by [`Participant::process_single_message()`] to the correct recipient.
///
/// [`Message`]s contain a `to: ParticipantIdentifier` field which specifies the
/// recipient of a message. The calling application is responsible for
/// maintaining a mapping from [`ParticipantIdentifier`]s to some network
/// metadata so outgoing messages can be routed to the correct `Participant`.
///
/// The calling application can pass messages for a [`Participant`] as soon as
/// it receives them. The library handles messages received "too early" -- that
/// is, before a `Participant` has completed the prerequisite rounds -- by
/// storing them in memory. Stored messages are retrieved automatically and
/// processed at the appropriate point in the protocol, when all prerequisites
/// have been satisfied.
///
/// # 🔒 Storage requirements
/// It is up to the calling application to persist outputs used by the
/// participant. In addition, some of the outputs are private to the
/// participant, and **these must be stored securely by the calling
/// application**. Which outputs require secure storage is documented by each
/// protocol type, under the "Storage requirements" heading:
/// [`KeygenParticipant`](crate::keygen::KeygenParticipant),
/// [`AuxInfoParticipant`](crate::auxinfo::AuxInfoParticipant), and
/// [`PresignParticipant`](crate::PresignParticipant). In addition, some outputs
/// must only be used once and then discarded. These are documented as necessary
/// under the "Lifetime requirements" heading in the aforementioned types.
///
/// ## Requirements of external storage
/// Any external storage must be able to achieve the following requirements:
/// - Encryption: Data is stored encrypted.
/// - Freshness: The storage contains the most recent state of the execution and
///   avoids replay attacks.
/// - Secure deletion: Data can be securely deleted from storage.
#[derive(Debug)]
pub struct Participant<P>
where
    P: ProtocolParticipant,
{
    /// An identifier for this participant.
    id: ParticipantIdentifier,

    /// The [`ProtocolParticipant`] driver defining the actual protocol
    /// execution.
    participant: P,
}

impl<P: ProtocolParticipant> Participant<P> {
    /// Initialize the participant from a [`ParticipantConfig`].
    pub fn from_config(
        config: ParticipantConfig,
        sid: Identifier,
        input: P::Input,
    ) -> Result<Self> {
        info!("Initializing participant from config.");

        let (id, other_ids) = config.into_parts();

        Ok(Participant {
            id,
            participant: P::new(sid, id, other_ids, input)?,
        })
    }

    /// Retrieve the [`ParticipantIdentifier`] for this `Participant`.
    pub fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    /// Retrieve the unique session [`Identifier`] for this `Participant`.
    pub fn sid(&self) -> Identifier {
        self.participant.sid()
    }

    /// Process the first message from the participant's inbox.
    ///
    /// ## Return type
    /// This returns a possible output and a set of messages:
    /// - The output holds the output of the protocol with the given session ID,
    ///   if it terminated for this participant.
    /// - The messages are a (possibly empty) list of messages to be sent out to
    ///   other participants.
    #[cfg_attr(feature = "flame_it", flame)]
    #[instrument(skip_all, err(Debug))]
    pub fn process_single_message<R: RngCore + CryptoRng>(
        &mut self,
        message: &Message,
        rng: &mut R,
    ) -> Result<(Option<P::Output>, Vec<Message>)> {
        info!("Processing single message.");

        // Check SID
        if message.id() != self.sid() {
            error!(
                "Message for session {} was routed to the wrong participant (sid: {})!",
                message.id(),
                self.sid()
            );
            Err(CallerError::WrongSessionId)?
        }

        // Check that message belongs to correct protocol
        match (message.message_type(), P::protocol_type()) {
            (MessageType::Auxinfo(_), ProtocolType::AuxInfo)
            | (MessageType::Keygen(_), ProtocolType::Keygen)
            | (MessageType::Presign(_), ProtocolType::Presign) => {}
            _ => {
                error!(
                    "Message type did not match type of this participant: got {:?}, expected {:?}",
                    message.message_type(),
                    P::protocol_type()
                );
                Err(CallerError::WrongProtocol)?
            }
        };

        // Check recipient
        if message.to() != self.id {
            Err(CallerError::WrongMessageRecipient)?
        }

        // Check that message is from a participant in this session
        if !self
            .participant
            .all_participants()
            .contains(&message.from())
        {
            Err(CallerError::InvalidMessageSender)?
        }

        // Handle it!
        let outcome = self.participant.process_message(rng, message)?;
        let (output, messages) = outcome.into_parts();
        Ok((output, messages))
    }

    /// Produce a message to signal to this participant that the protocol can
    /// begin.
    #[instrument(skip_all)]
    pub fn initialize_message(&self) -> Result<Message> {
        info!("Initializing subprotocol.");
        let empty: [u8; 0] = [];
        Message::new(P::ready_type(), self.sid(), self.id, self.id, &empty)
    }

    /// Return the protocol status.
    pub fn status(&self) -> &P::Status {
        self.participant.status()
    }
}

/// A share of the ECDSA signature.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignatureShare {
    /// The x-projection of `R` from the [`PresignRecord`](crate::PresignRecord)
    /// (`r` in the paper).
    ///
    /// Note: The paper does _not_ include this as part of the share, and
    /// instead, a signature share is just the `σ` value. We include this value
    /// here in order to allow any party, not necessarily one of the
    /// participants who created a share, to be able to reconstruct the
    /// signature.
    r: k256::Scalar,
    /// The digest masked by components from
    /// [`PresignRecord`](crate::PresignRecord) (`σ` in the paper).
    s: k256::Scalar,
}

impl SignatureShare {
    /// Creates a new [`SignatureShare`].
    pub(crate) fn new(r: k256::Scalar, s: k256::Scalar) -> Self {
        SignatureShare { r, s }
    }

    /// Turn a vector of [`SignatureShare`]s into an ECDSA
    /// [`Signature`](k256::ecdsa::Signature).
    ///
    ///
    /// Note: This method does _not_ validate the signature. This deviates from
    /// the protocol as written, which validates the signature once is has been
    /// created from the signature shares. By not including this step we lose
    /// the ability to preform identifiable abort, as specified in the protocol
    /// description.
    pub fn into_signature(
        shares: impl Iterator<Item = SignatureShare>,
    ) -> Result<k256::ecdsa::Signature> {
        shares
            .into_iter()
            // Currently, because `chain` returns `Result`, we need to wrap all
            // items in `Ok` for the `reduce` call below to work. This is ugly!
            // If we change `chain` to not be able to fail we can remove this
            // extra `map`.
            .map(Ok)
            .reduce(|acc, share| acc?.chain(share?))
            .ok_or_else(|| {
                error!("Zero length iterator provided as input");
                InternalError::InternalInvariantFailed
            })??
            .finish()
    }

    /// Can be used to combine [`SignatureShare`]s.
    fn chain(&self, share: Self) -> Result<Self> {
        if self.r != share.r {
            error!(
                "Failed to chain signature shares together because 
                        r-values were different. Got {:?}, expected {:?}.",
                &self.r, share.r
            );
            return Err(InternalError::InternalInvariantFailed);
        }

        // Keep the same r, add in the s value
        Ok(Self::new(self.r, self.s + share.s))
    }

    /// Convert the [`SignatureShare`] into an ECDSA signature.
    #[instrument(skip_all err(Debug))]
    fn finish(self) -> Result<k256::ecdsa::Signature> {
        info!("Converting signature share into a signature.");
        let mut s = self.s;
        if bool::from(s.is_high()) {
            s = s.negate();
        }
        k256::ecdsa::Signature::from_scalars(self.r, s).map_err(|_| {
            error!("Unable to create ECDSA signature from provided r and s");
            InternalError::InternalInvariantFailed
        })
    }
}

pub(crate) mod participant_config {
    use super::*;

    /// The configuration for the participant.
    ///
    /// Contains a set of at least two unique participant identifiers.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ParticipantConfig {
        /// The identifier for this participant.
        id: ParticipantIdentifier,
        /// The identifier for the other participants executing the protocol.
        other_ids: Vec<ParticipantIdentifier>,
    }

    impl ParticipantConfig {
        /// Get the [`ParticipantIdentifier`] for the owner of this config.
        pub fn id(&self) -> ParticipantIdentifier {
            self.id
        }

        /// Get the [`ParticipantIdentifier`] for all other participants.
        pub fn other_ids(&self) -> &[ParticipantIdentifier] {
            self.other_ids.as_slice()
        }

        /// Returns a list of all participant IDs, including `self`'s.
        pub fn all_participants(&self) -> Vec<ParticipantIdentifier> {
            let mut participant = self.other_ids().to_owned();
            participant.push(self.id());
            participant
        }

        pub(crate) fn into_parts(self) -> (ParticipantIdentifier, Vec<ParticipantIdentifier>) {
            (self.id, self.other_ids)
        }

        /// Create a new [`ParticipantConfig`].
        ///
        /// The protocol requires at least two participants; `other_ids` cannot
        /// be empty. All participant identifiers must be unique.
        pub fn new(id: ParticipantIdentifier, other_ids: &[ParticipantIdentifier]) -> Result<Self> {
            if other_ids.is_empty() {
                error!(
                    "Tried to create a participant config with too few participants. There must be at least one `other_id`.",
                );
                Err(CallerError::ParticipantConfigError)?
            }

            // Test for uniqueness
            let unique_set =
                HashSet::<&ParticipantIdentifier>::from_iter(std::iter::once(&id).chain(other_ids));
            if unique_set.len() != other_ids.len() + 1 {
                error!(
                    "Tried to create a participant config with a non-unique set of participants"
                );
                Err(CallerError::ParticipantConfigError)?
            }

            Ok(Self {
                id,
                other_ids: other_ids.to_vec(),
            })
        }

        /// Get a list of `size` consistent [`ParticipantConfig`]s.
        ///
        /// Each config contains a different permutation of a single overall set
        /// of [`ParticipantIdentifier`]s.
        ///
        /// **⚠️ Security warning:** This method implies the existence of a
        /// trusted third party that generates the participant IDs. This
        /// method must not be used if your deployment does not have a
        /// trusted party.
        pub fn random_quorum<R: RngCore + CryptoRng>(
            size: usize,
            rng: &mut R,
        ) -> Result<Vec<ParticipantConfig>> {
            if size < 2 {
                Err(CallerError::ParticipantConfigError)?
            }
            let ids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
                .take(size)
                .collect::<Vec<_>>();

            (0..size)
                .map(|i| {
                    let mut other_ids = ids.clone();
                    let id = other_ids.swap_remove(i);
                    Self::new(id, other_ids.as_slice())
                })
                .collect::<Result<_>>()
        }

        ///Create a random [`ParticipantConfig`].
        #[cfg(test)]
        pub(crate) fn random<R: RngCore + CryptoRng>(
            size: usize,
            rng: &mut R,
        ) -> ParticipantConfig {
            assert!(size > 1);
            let other_ids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
                .take(size - 1)
                .collect::<Vec<_>>();
            let id = ParticipantIdentifier::random(rng);
            Self { id, other_ids }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::utils::testing::init_testing;

        #[test]
        fn participant_config_must_have_at_least_two_participants() {
            let mut rng = init_testing();
            let result = ParticipantConfig::new(ParticipantIdentifier::random(&mut rng), &[]);
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                InternalError::CallingApplicationMistake(CallerError::ParticipantConfigError)
            );
        }

        #[test]
        fn participant_config_must_have_unique_participants() {
            let mut rng = init_testing();
            let id = ParticipantIdentifier::random(&mut rng);
            let result = ParticipantConfig::new(id, &[id]);
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                InternalError::CallingApplicationMistake(CallerError::ParticipantConfigError)
            );

            let result = ParticipantConfig::new(ParticipantIdentifier::random(&mut rng), &[id, id]);
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                InternalError::CallingApplicationMistake(CallerError::ParticipantConfigError)
            );
        }

        // Testing whether Participant Config has at least 2 participants
        #[test]
        fn random_quorum_must_have_at_least_two_participants() {
            let mut rng = init_testing();
            for i in 0..2 {
                let result = ParticipantConfig::random_quorum(i, &mut rng);
                assert!(result.is_err());
                assert_eq!(
                    result.unwrap_err(),
                    InternalError::CallingApplicationMistake(CallerError::ParticipantConfigError)
                );
            }
        }
    }
}

/// An identifier for a [`Participant`].
///
/// All [`Participant`]s in a session must agree on the
/// [`ParticipantIdentifier`]s. That is, these are not local identifiers
/// controlled by a single `Participant`; they are unique, agreed-upon
/// identifiers for the `Participant`s in a session. Each entity participating
/// in a session should have a different `ParticipantIdentifier`.
///
/// `ParticipantIdentifier`s can be used across multiple sessions. For
/// example, if a set of participants run keygen, auxinfo, and then compute
/// several signatures, they can use the same set of identifiers for each of
/// those sessions. However, a single `ParticipantIdentifier` should not be used
/// to represent different entities (even in different sessions with
/// non-overlapping participant sets!).
///
/// `ParticipantIdentifier`s should be unique within a deployment, but they
/// don't necessarily have to be globally unique.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParticipantIdentifier(u128);

impl ParticipantIdentifier {
    /// Generates a random [`ParticipantIdentifier`].
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<u128>();
        trace!("Created new Participant Identifier({random_bytes})");
        Self(random_bytes)
    }
}

/// The `SharedContext` contains fixed known parameters across the entire
/// protocol. It does not however contain the entire protocol context.
#[derive(Debug)]
pub(crate) struct SharedContext {
    sid: Identifier,
    participants: Vec<ParticipantIdentifier>,
    generator: CurvePoint,
    order: BigNumber,
}
impl ProofContext for SharedContext {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok([
            self.sid.0.to_be_bytes().into_iter().collect(),
            self.participants
                .iter()
                .flat_map(|pid| pid.0.to_le_bytes())
                .collect(),
            bincode::serialize(&self.generator)
                .map_err(|_| InternalError::InternalInvariantFailed)?,
            self.order.to_bytes(),
        ]
        .concat())
    }
}

impl SharedContext {
    pub(crate) fn collect<P: InnerProtocolParticipant>(p: &P) -> Self {
        let mut participants = p.all_participants();
        participants.sort();
        let generator = CurvePoint::GENERATOR;
        let order = k256_order();
        SharedContext {
            sid: p.sid(),
            participants,
            generator,
            order,
        }
    }
    #[cfg(test)]
    pub fn fill_context(mut participants: Vec<ParticipantIdentifier>, sid: Identifier) -> Self {
        participants.sort();
        SharedContext {
            sid,
            participants,
            generator: CurvePoint::GENERATOR,
            order: k256_order(),
        }
    }
}

impl std::fmt::Display for ParticipantIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ParticipantId({})",
            hex::encode(&self.0.to_be_bytes()[..4])
        )
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]

/// A session [`Identifier`] uniquely identifies a single
/// instance of a protocol and all messages associated with it.
///
/// Session identifiers have two roles in the protocol: they tag messages
/// and they are incorporated as context into zero-knowledge proofs.
/// They must be _globally unique_; this allows participants to distinguish
/// messages belonging to different, concurrent protocol runs,
/// prevents collisions between messages belonging to
/// different sessions, and prevents replay attacks by associating messages and
/// zero-knowledge proofs
/// with the session, fixed parameters, and previous subprotocols to which
/// they correspond. Global uniqueness is required in order to achieve
/// universally-composable (UC) security, the paradigm used by the paper to
/// prove security of the protocol.
///
/// 🔒 It is the responsibility of the calling application to pick session
/// identifiers. The calling application must select a protocol with
/// appropriate trust assumptions for its deployment to ensure the chosen
/// [`Identifier`] is unique and that all parties have the same one.
/// Sample protocols (with varying trust models!) could include:
/// - A trusted party randomly samples a unique identifier with
///   `Identifier::random()` and sends it to all parties;
/// - The participants run a Byzantine agreement protocol.
///
/// # Discrepancies with the paper with respect to session identifiers:
/// The paper defines session identifiers, denoted `sid` and `ssid`, somewhat
/// differently that we implement them in this codebase. We believe the
/// implementation achieves the same guarantees that the paper describes.
///
/// 1. The paper incorporates many types of data into its session and
/// sub-session identifiers, including fixed parameters, the participant set,
/// and key- and party-specific parameters that the calling application
/// persists[^outs]; these identifiers are used both to tag
/// messages and incorporate context into proofs. The codebase defines a single
/// `Identifier` type; this is a global, unique identifier
/// used to tag messages. The other fields (as well as
/// the `Identifier`) are incorporated into proofs using a different mechanism
/// to define the proof context.
///
/// 2. The paper distinguishes between identifiers for sessions (keygen) and
/// sub-sessions (auxinfo and presign)[^bug].
/// The codebase requires the calling application to select a new, unique
/// session [`Identifier`]s at three points:
/// (1) immediately before starting a new keygen session;
/// (2) immediately before starting a new auxinfo session;
/// (3) immediately before starting a new presigning session (for use in
/// presigning and the subsequent signature).
///
///
/// 3. 🔒 In the paper, `ssid` is updated each time the participants run the
/// key-refresh subprotocol.
/// The codebase relies on the calling application to generate a new, unique
/// `Identifier` for each new session.
///
/// [^outs]: These can include public key shares and shared randomness that were
/// returned as output from a previous run of keygen and public commitment
/// parameters that were returned as output from a previous run of auxinfo.
///
/// [^bug]: In fact, we think there is a minor bug in Figure 6 of the paper, since
/// the definition of `ssid` includes outputs of auxinfo, and thus cannot be
/// passed as input to auxinfo. We believe the correct instantiation of the
/// `ssid` for auxinfo is in Figure 3, which includes fixed parameters (`sid`)
/// and outputs from keygen, but _not_ outputs from auxinfo.
pub struct Identifier(u128);

impl Debug for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Id({})", hex::encode(&self.0.to_le_bytes()[..4]))
    }
}

impl Identifier {
    /// Produces an [`Identifier`] chosen uniformly at random.
    ///
    /// **⚠️ Security warning:** This method implies the existence of a trusted
    /// third party that generates session IDs and correctly distributes
    /// them to all participants. This method must not be used if your
    /// deployment does not have a trusted party.
    #[instrument(skip_all)]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<u128>();
        trace!("Created new Session Identifier({random_bytes})");
        Self(random_bytes)
    }
}

impl From<u128> for Identifier {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Id({})", hex::encode(&self.0.to_be_bytes()[..4]))
    }
}

#[cfg(test)]
#[allow(unknown_lints)]
mod tests {
    use super::*;
    use crate::{
        auxinfo::{self, AuxInfoParticipant},
        keygen::KeygenParticipant,
        presign::participant::Input as PresignInput,
        utils::testing::init_testing,
        PresignParticipant,
    };
    use k256::ecdsa::signature::DigestVerifier;
    use rand::seq::IteratorRandom;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use tracing::debug;

    // Negative test checking whether the message has the correct session id
    #[test]
    fn participant_rejects_messages_with_wrong_session_id() -> Result<()> {
        let mut rng = init_testing();
        let QUORUM_SIZE = 3;

        // Set up a single valid participant
        let config = ParticipantConfig::random(QUORUM_SIZE, &mut rng);
        let auxinfo_sid = Identifier::random(&mut rng);
        let mut participant =
            Participant::<AuxInfoParticipant>::from_config(config, auxinfo_sid, ()).unwrap();

        // Make a message with the wrong session ID
        let message = participant.initialize_message()?;
        let bad_sid = Identifier::random(&mut rng);
        assert_ne!(bad_sid, message.id());
        let bad_sid_message = Message::new(
            message.message_type,
            bad_sid,
            message.from(),
            message.to(),
            &message.unverified_bytes,
        )?;

        // Make sure the participant rejects the message
        let result = participant.process_single_message(&bad_sid_message, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::WrongSessionId)
        );
        Ok(())
    }

    // Negative test checking whether the message has the correct recipient
    // participant
    #[test]
    fn participant_rejects_messages_with_wrong_participant_to_field() -> Result<()> {
        let mut rng = init_testing();
        let QUORUM_SIZE = 3;

        // Set up a single valid participant
        let config = ParticipantConfig::random(QUORUM_SIZE, &mut rng);
        let auxinfo_sid = Identifier::random(&mut rng);
        let mut participant =
            Participant::<AuxInfoParticipant>::from_config(config, auxinfo_sid, ()).unwrap();

        // Make a message with the wrong participant to field
        let message = participant.initialize_message()?;
        let bad_receiver_pid = ParticipantIdentifier::random(&mut rng);
        assert_ne!(participant.id(), bad_receiver_pid);
        let bad_receiver_pid_message = Message::new(
            message.message_type,
            message.id(),
            message.from(),
            bad_receiver_pid,
            &message.unverified_bytes,
        )?;

        // Make sure the participant rejects the message
        let result = participant.process_single_message(&bad_receiver_pid_message, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::WrongMessageRecipient)
        );
        Ok(())
    }

    // Negative test checking whether the message has the correct protocol type
    #[test]
    fn participant_rejects_messages_with_wrong_protocol_type() -> Result<()> {
        let mut rng = init_testing();
        let QUORUM_SIZE = 3;

        // Set up a single valid participant
        let config = ParticipantConfig::random(QUORUM_SIZE, &mut rng);
        let auxinfo_sid = Identifier::random(&mut rng);
        let mut participant =
            Participant::<AuxInfoParticipant>::from_config(config, auxinfo_sid, ()).unwrap();

        // Make a message with the wrong protocol type
        let message = participant.initialize_message()?;
        let bad_message_type =
            MessageType::Keygen(crate::messages::KeygenMessageType::R1CommitHash);
        let bad_protocol_type_message = Message::new(
            bad_message_type,
            message.id(),
            message.from(),
            message.to(),
            &message.unverified_bytes,
        )?;

        // Make sure the participant rejects the message
        let result = participant.process_single_message(&bad_protocol_type_message, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::WrongProtocol)
        );
        Ok(())
    }

    // Negative test checking whether the message sender is included in the list of
    // all participants
    #[test]
    fn participant_rejects_messages_with_wrong_sender_participant() -> Result<()> {
        let mut rng = init_testing();
        let QUORUM_SIZE = 3;

        // Set up a single valid participant
        let config = ParticipantConfig::random(QUORUM_SIZE, &mut rng);
        let auxinfo_sid = Identifier::random(&mut rng);
        let mut participant =
            Participant::<AuxInfoParticipant>::from_config(config, auxinfo_sid, ()).unwrap();

        //message with the wrong sender participant
        let message = participant.initialize_message()?;
        let bad_sender_pid = ParticipantIdentifier::random(&mut rng);
        let bad_sender_pid_message = Message::new(
            message.message_type(),
            message.id(),
            bad_sender_pid,
            message.to(),
            &message.unverified_bytes,
        )?;

        // Make sure the participant rejects the message
        let result = participant.process_single_message(&bad_sender_pid_message, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::InvalidMessageSender)
        );
        Ok(())
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
    fn process_messages<R: RngCore + CryptoRng, P: ProtocolParticipant>(
        quorum: &mut [Participant<P>],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
    ) -> Result<Option<(ParticipantIdentifier, P::Output)>> {
        // Pick a random participant to process
        let participant = quorum.iter_mut().choose(rng).unwrap();

        let inbox = inboxes.get_mut(&participant.id).unwrap();
        if inbox.is_empty() {
            // No messages to process for this participant, so pick another participant
            return Ok(None);
        }

        // Process a random message in the participant's inbox
        // This is done to simulate arbitrary message arrival ordering
        let index = rng.gen_range(0..inbox.len());
        let message = inbox.remove(index);
        debug!(
            "message from {} to {}, with type: {:?}",
            &message.from(),
            &participant.id,
            &message.message_type(),
        );
        let (output, messages) = participant.process_single_message(&message, rng)?;
        deliver_all(&messages, inboxes)?;

        // Return the (id, output) pair, so the calling application knows _who_
        // finished.
        Ok(output.map(|out| (participant.id, out)))
    }

    fn inboxes_are_empty(inboxes: &HashMap<ParticipantIdentifier, Vec<Message>>) -> bool {
        inboxes.iter().all(|(_pid, messages)| messages.is_empty())
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    fn full_protocol_execution_works() -> Result<()> {
        let mut rng = init_testing();
        let QUORUM_SIZE = 3;
        // Set GLOBAL config for participants
        let configs = ParticipantConfig::random_quorum(QUORUM_SIZE, &mut rng).unwrap();

        // Set up auxinfo participants
        let auxinfo_sid = Identifier::random(&mut rng);
        let mut auxinfo_quorum = configs
            .clone()
            .into_iter()
            .map(|config| {
                Participant::<AuxInfoParticipant>::from_config(config, auxinfo_sid, ()).unwrap()
            })
            .collect::<Vec<_>>();

        let mut inboxes: HashMap<ParticipantIdentifier, Vec<Message>> = HashMap::from_iter(
            auxinfo_quorum
                .iter()
                .map(|p| (p.id, vec![]))
                .collect::<Vec<_>>(),
        );

        let mut auxinfo_outputs: HashMap<
            ParticipantIdentifier,
            <AuxInfoParticipant as ProtocolParticipant>::Output,
        > = HashMap::new();

        // Initialize auxinfo for all parties
        for participant in &auxinfo_quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_message()?);
        }

        // Run auxinfo until all parties have outputs
        while auxinfo_outputs.len() < QUORUM_SIZE {
            let output = process_messages(&mut auxinfo_quorum, &mut inboxes, &mut rng)?;

            if let Some((pid, output)) = output {
                // Save the output, and make sure this participant didn't already return an
                // output.
                assert!(auxinfo_outputs.insert(pid, output).is_none());
            }
        }

        // Auxinfo is done! Make sure there are no more messages.
        assert!(inboxes_are_empty(&inboxes));
        // And make sure all participants have successfully terminated.
        assert!(auxinfo_quorum
            .iter()
            .all(|p| *p.status() == auxinfo::Status::TerminatedSuccessfully));

        // Set up keygen participants
        let keygen_sid = Identifier::random(&mut rng);
        let mut keygen_quorum = configs
            .clone()
            .into_iter()
            .map(|config| {
                Participant::<KeygenParticipant>::from_config(config, keygen_sid, ()).unwrap()
            })
            .collect::<Vec<_>>();
        let mut keygen_outputs: HashMap<
            ParticipantIdentifier,
            <KeygenParticipant as ProtocolParticipant>::Output,
        > = HashMap::new();

        // Initialize keygen for all participants
        for participant in &keygen_quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_message()?);
        }

        // Run keygen until all parties have outputs
        while keygen_outputs.len() < QUORUM_SIZE {
            let output = process_messages(&mut keygen_quorum, &mut inboxes, &mut rng)?;

            if let Some((pid, output)) = output {
                // Save the output, and make sure this participant didn't already return an
                // output.
                assert!(keygen_outputs.insert(pid, output).is_none());
            }
        }

        // Keygen is done! Makre sure there are no more messages.
        assert!(inboxes_are_empty(&inboxes));
        // And make sure all participants have successfully terminated.
        assert!(keygen_quorum
            .iter()
            .all(|p| *p.status() == crate::keygen::Status::TerminatedSuccessfully));

        // Save the public key for later
        let saved_public_key = keygen_outputs
            .get(&configs.get(0).unwrap().id())
            .unwrap()
            .public_key()?;

        // Set up presign participants
        let presign_sid = Identifier::random(&mut rng);

        // Prepare presign inputs: a pair of outputs from keygen and auxinfo.
        let presign_inputs = configs
            .iter()
            .map(|config| {
                (
                    auxinfo_outputs.remove(&config.id()).unwrap(),
                    keygen_outputs.remove(&config.id()).unwrap(),
                )
            })
            .map(|(auxinfo_output, keygen_output)| {
                PresignInput::new(auxinfo_output, keygen_output).unwrap()
            })
            .collect::<Vec<_>>();

        let mut presign_quorum = configs
            .into_iter()
            .zip(presign_inputs)
            .map(|(config, input)| {
                Participant::<PresignParticipant>::from_config(config, presign_sid, input).unwrap()
            })
            .collect::<Vec<_>>();
        let mut presign_outputs: HashMap<
            ParticipantIdentifier,
            <PresignParticipant as ProtocolParticipant>::Output,
        > = HashMap::new();

        for participant in &mut presign_quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_message()?);
        }

        while presign_outputs.len() < QUORUM_SIZE {
            let output = process_messages(&mut presign_quorum, &mut inboxes, &mut rng)?;

            if let Some((pid, output)) = output {
                // Save the output, and make sure this participant didn't already return an
                // output.
                assert!(presign_outputs.insert(pid, output).is_none());
            }
        }

        // Presigning is done! Make sure there are no more messages.
        assert!(inboxes_are_empty(&inboxes));
        // And make sure all participants have successfully terminated.
        assert!(presign_quorum
            .iter()
            .all(|p| *p.status() == crate::presign::participant::Status::TerminatedSuccessfully));

        // Now, produce a valid signature
        let mut hasher = Sha256::new();
        hasher.update(b"some test message");

        let shares = presign_outputs
            .into_values()
            .map(|record| record.sign(hasher.clone()).unwrap());
        let signature = SignatureShare::into_signature(shares)?;

        // Moment of truth, does the signature verify?
        assert!(saved_public_key.verify_digest(hasher, &signature).is_ok());

        #[cfg(feature = "flame_it")]
        flame::dump_html(&mut std::fs::File::create("dev/flame-graph.html").unwrap()).unwrap();
        Ok(())
    }
}
