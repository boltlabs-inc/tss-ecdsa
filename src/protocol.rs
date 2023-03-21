// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main protocol that is executed through a [Participant]

use crate::{
    auxinfo::{
        info::{AuxInfoPrivate, AuxInfoPublic},
        participant::AuxInfoParticipant,
    },
    errors::{InternalError, Result},
    keygen::{
        keyshare::{KeySharePrivate, KeySharePublic},
        participant::KeygenParticipant,
    },
    messages::{AuxinfoMessageType, KeygenMessageType, MessageType},
    participant::ProtocolParticipant,
    presign::{
        participant::{Input as PresignInput, PresignParticipant},
        record::PresignRecord,
    },
    storage::{PersistentStorageType, Storage},
    utils::CurvePoint,
    Message,
};
use k256::elliptic_curve::{Field, IsHigh};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use tracing::{error, info, instrument, trace};

/////////////////////
// Participant API //
/////////////////////

/// Each participant has an inbox which can contain messages.
#[derive(Debug)]
pub struct Participant {
    /// A unique identifier for this participant
    pub id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    pub other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store finalized auxinfo, keygen,
    /// and presign values. This storage is not responsible for storing
    /// round-specific material.
    main_storage: Storage,
    /// Participant subprotocol for handling auxinfo messages
    auxinfo_participant: AuxInfoParticipant,
    /// Participant subprotocol for handling keygen messages
    keygen_participant: KeygenParticipant,
    /// Participant subprotocol for handling presign messages
    presign_participant: PresignParticipant,
}

impl Participant {
    /// Initialized the participant from a [ParticipantConfig]
    #[instrument(err(Debug))]
    pub fn from_config(config: ParticipantConfig) -> Result<Self> {
        info!("Initializing participant from config.");

        Ok(Participant {
            id: config.id,
            other_participant_ids: config.other_ids.clone(),
            main_storage: Storage::new(),
            auxinfo_participant: AuxInfoParticipant::from_ids(config.id, config.other_ids.clone()),
            keygen_participant: KeygenParticipant::from_ids(config.id, config.other_ids.clone()),
            presign_participant: PresignParticipant::from_ids(config.id, config.other_ids),
        })
    }

    /// Instantiate a new quorum of participants of a specified size. Random
    /// identifiers are selected
    #[instrument(skip_all, err(Debug))]
    pub fn new_quorum<R: RngCore + CryptoRng>(
        quorum_size: usize,
        rng: &mut R,
    ) -> Result<Vec<Self>> {
        info!("Instantiating new quorum of size {quorum_size}");

        let mut participant_ids = vec![];
        for _ in 0..quorum_size {
            participant_ids.push(ParticipantIdentifier::random(rng));
        }
        let participants = participant_ids
            .iter()
            .map(|&participant_id| -> Result<Participant> {
                // Filter out current participant id from list of other ids
                let mut other_ids = vec![];
                for &id in participant_ids.iter() {
                    if id != participant_id {
                        other_ids.push(id);
                    }
                }

                Self::from_config(ParticipantConfig {
                    id: participant_id,
                    other_ids,
                })
            })
            .collect::<Result<Vec<Participant>>>()?;
        Ok(participants)
    }

    /// Processes the first message from the participant's inbox.
    ///
    /// ## Return type
    /// This returns a tuple of a session ID, an output, and a set of messages.
    /// - The session ID will always match the session ID of the input message,
    ///   and of all the outgoing messages. It's passed out as a convenience for
    ///   associating with the [`Output`].
    /// - The [`Output`] encodes the termination status and any outputs of the
    ///   protocol with the given session ID.
    /// - The messages are a (possibly empty) list of messages to be sent out to
    ///   other participants.
    #[cfg_attr(feature = "flame_it", flame)]
    #[instrument(skip_all, err(Debug))]
    pub fn process_single_message<R: RngCore + CryptoRng>(
        &mut self,
        message: &Message,
        rng: &mut R,
    ) -> Result<(Identifier, Output, Vec<Message>)> {
        info!("Processing single message.");

        if message.to() != self.id {
            return Err(InternalError::WrongMessageRecipient);
        }
        match message.message_type() {
            MessageType::Auxinfo(_) => {
                let outcome = self
                    .auxinfo_participant
                    .process_message(rng, message, &())?;
                let (output, messages) = outcome.into_parts();
                let public_output = match output {
                    Some((auxinfo_publics, auxinfo_private)) => {
                        // TODO #180: Remove once we've removed the use of main storage.
                        for auxinfo_public in &auxinfo_publics {
                            self.main_storage.store(
                                PersistentStorageType::AuxInfoPublic,
                                message.id(),
                                *auxinfo_public.participant(),
                                auxinfo_public,
                            )?;
                        }
                        self.main_storage.store(
                            PersistentStorageType::AuxInfoPrivate,
                            message.id(),
                            self.id,
                            &auxinfo_private,
                        )?;
                        Output::AuxInfo(auxinfo_publics, auxinfo_private)
                    }
                    None => Output::None,
                };
                Ok((message.id(), public_output, messages))
            }
            MessageType::Keygen(_) => {
                let outcome = self.keygen_participant.process_message(rng, message, &())?;
                let (output, messages) = outcome.into_parts();
                let public_output = match output {
                    Some((keyshare_publics, keyshare_private)) => {
                        // TODO #180: Remove once we've removed the use of main storage.
                        for keyshare_public in &keyshare_publics {
                            self.main_storage.store(
                                PersistentStorageType::PublicKeyshare,
                                message.id(),
                                keyshare_public.participant(),
                                keyshare_public,
                            )?;
                        }
                        self.main_storage.store(
                            PersistentStorageType::PrivateKeyshare,
                            message.id(),
                            self.id,
                            &keyshare_private,
                        )?;
                        Output::KeyGen(keyshare_publics, keyshare_private)
                    }
                    None => Output::None,
                };
                Ok((message.id(), public_output, messages))
            }
            MessageType::Presign(_) => {
                let input = self.construct_presign_input(message.id())?;
                let outcome = self
                    .presign_participant
                    .process_message(rng, message, &input)?;

                let (output, messages) = outcome.into_parts();

                let public_output = match output {
                    Some(record) => {
                        self.main_storage.store(
                            PersistentStorageType::PresignRecord,
                            message.id(),
                            self.id,
                            &record,
                        )?;
                        Output::Presign(record)
                    }
                    None => Output::None,
                };
                Ok((message.id(), public_output, messages))
            }
            _ => Err(InternalError::MisroutedMessage),
        }
    }

    /// Produces a message to signal to this participant that auxinfo generation
    /// is ready for the specified identifier.
    #[instrument(skip_all)]
    pub fn initialize_auxinfo_message(&self, auxinfo_identifier: Identifier) -> Message {
        info!("Auxinfo generation is ready.");
        Message::new(
            MessageType::Auxinfo(AuxinfoMessageType::Ready),
            auxinfo_identifier,
            self.id,
            self.id,
            &[],
        )
    }

    /// Produces a message to signal to this participant that keyshare
    /// generation is ready for the specified identifier
    #[instrument(skip_all)]
    pub fn initialize_keygen_message(&self, keygen_identifier: Identifier) -> Message {
        info!("Keyshare generation is ready.");
        Message::new(
            MessageType::Keygen(KeygenMessageType::Ready),
            keygen_identifier,
            self.id,
            self.id,
            &[],
        )
    }

    /// Produces a message to signal to this participant that presignature
    /// generation is ready for the specified identifier. This also requires
    /// supplying the associated auxinfo identifier and keyshare identifier.
    /// `auxinfo_identifier`, `keyshare_identifier` and `identifier` correspond
    /// to session identifiers.
    #[instrument(skip_all)]
    pub fn initialize_presign_message(
        &mut self,
        auxinfo_identifier: Identifier,
        keyshare_identifier: Identifier,
        identifier: Identifier,
    ) -> Result<Message> {
        info!("Presignature generation is ready.");
        self.presign_participant.initialize_presign_message(
            auxinfo_identifier,
            keyshare_identifier,
            identifier,
        )
    }

    /// Returns true if auxinfo generation has completed for this identifier
    #[instrument(skip_all)]
    pub fn is_auxinfo_done(&self, auxinfo_identifier: Identifier) -> Result<bool> {
        let mut fetch = vec![];
        for participant in self.auxinfo_participant.all_participants() {
            fetch.push((
                PersistentStorageType::AuxInfoPublic,
                auxinfo_identifier,
                participant,
            ));
        }
        fetch.push((
            PersistentStorageType::AuxInfoPrivate,
            auxinfo_identifier,
            self.id,
        ));

        self.main_storage.contains_batch(&fetch)
    }

    /// Returns true if keyshare generation has completed for this identifier
    #[instrument(skip_all)]
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

        self.main_storage.contains_batch(&fetch)
    }

    /// Returns true if presignature generation has completed for this
    /// identifier
    #[instrument(skip_all)]
    pub fn is_presigning_done(&self, presign_identifier: Identifier) -> Result<bool> {
        self.main_storage.contains_batch(&[(
            PersistentStorageType::PresignRecord,
            presign_identifier,
            self.id,
        )])
    }

    /// Retrieves this participant's associated public keyshare for this
    /// identifier
    #[instrument(skip_all, err(Debug))]
    pub fn get_public_keyshare(&self, identifier: Identifier) -> Result<CurvePoint> {
        info!("Retrieving our associated public keyshare.");
        let keyshare_public: KeySharePublic = self.main_storage.retrieve(
            PersistentStorageType::PublicKeyshare,
            identifier,
            self.id,
        )?;
        Ok(keyshare_public.X)
    }

    /// If presign record is populated, then this participant is ready to issue
    /// a signature
    /// The `presign_identifier` globally and uniquely defines a session for
    /// the pre-signing.
    #[instrument(skip_all, err(Debug))]
    pub fn sign(
        &mut self,
        presign_identifier: Identifier,
        digest: sha2::Sha256,
    ) -> Result<SignatureShare> {
        info!("Issuing signature with presign record.");

        let presign_record: PresignRecord = self.main_storage.retrieve(
            PersistentStorageType::PresignRecord,
            presign_identifier,
            self.id,
        )?;
        // Clear the presign record after being used once
        let _ = self.main_storage.delete(
            PersistentStorageType::PresignRecord,
            presign_identifier,
            self.id,
        )?;
        let (r, s) = presign_record.sign(digest)?;
        let ret = SignatureShare { r: Some(r), s };

        Ok(ret)
    }

    /// Constructs [`PresignInput`] from the necessary stored data.
    fn construct_presign_input(&self, sid: Identifier) -> Result<PresignInput> {
        let (auxinfo_id, keygen_id) = self.presign_participant.get_associated_identifiers(&sid)?;
        let keyshare_private = self.main_storage.retrieve(
            PersistentStorageType::PrivateKeyshare,
            keygen_id,
            self.id,
        )?;
        let keyshare_publics = self.main_storage.retrieve_for_all_ids(
            PersistentStorageType::PublicKeyshare,
            keygen_id,
            &self.all_participants(),
        )?;
        let auxinfo_private = self.main_storage.retrieve(
            PersistentStorageType::AuxInfoPrivate,
            auxinfo_id,
            self.id,
        )?;
        let auxinfo_publics = self.main_storage.retrieve_for_all_ids(
            PersistentStorageType::AuxInfoPublic,
            auxinfo_id,
            &self.all_participants(),
        )?;
        PresignInput::new(
            auxinfo_publics,
            auxinfo_private,
            keyshare_publics,
            keyshare_private,
        )
    }

    fn all_participants(&self) -> Vec<ParticipantIdentifier> {
        let mut pids = self.other_participant_ids.clone();
        pids.push(self.id);
        pids
    }
}

/// Simple wrapper around the signature share output
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignatureShare {
    /// The r-scalar associated with an ECDSA signature
    pub r: Option<k256::Scalar>,
    /// The s-scalar associated with an ECDSA signature
    pub s: k256::Scalar,
}

impl Default for SignatureShare {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureShare {
    fn new() -> Self {
        Self {
            r: None,
            s: k256::Scalar::zero(),
        }
    }

    /// Can be used to combine [SignatureShare]s
    pub fn chain(&self, share: Self) -> Result<Self> {
        let r = match (self.r, share.r) {
            (_, None) => {
                error!("Input share was not initialized");
                Err(InternalError::InternalInvariantFailed)
            }
            (Some(prev_r), Some(new_r)) => {
                if prev_r != new_r {
                    return Err(InternalError::SignatureInstantiationError);
                }
                Ok(prev_r)
            }
            (None, Some(new_r)) => Ok(new_r),
        }?;

        // Keep the same r, add in the s value
        Ok(Self {
            r: Some(r),
            s: self.s + share.s,
        })
    }

    /// Converts the [SignatureShare] into a signature
    #[instrument(skip_all err(Debug))]
    pub fn finish(&self) -> Result<k256::ecdsa::Signature> {
        info!("Converting signature share into a signature.");
        let mut s = self.s;
        if bool::from(s.is_high()) {
            s = s.negate();
        }
        let r = self.r.ok_or(InternalError::NoChainedShares)?;

        k256::ecdsa::Signature::from_scalars(r, s)
            .map_err(|_| InternalError::SignatureInstantiationError)
    }
}

/// The configuration for the participant, including the identifiers
/// corresponding to the other participants of the quorum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantConfig {
    /// The identifier for this participant
    pub id: ParticipantIdentifier,
    /// The identifiers for the other participants of the quorum
    pub other_ids: Vec<ParticipantIdentifier>,
}

/// An identifier corresponding to a [Participant]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantIdentifier(u128);

impl ParticipantIdentifier {
    /// Generates a random [ParticipantIdentifier]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<u128>();
        trace!("Created new Participant Identifier({random_bytes})");
        Self(random_bytes)
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

/// An [`Identifier`] is a session identifier that uniquely identifies a single
/// instance of a protocol and all messages associated with it.
///
/// [`Identifier`] are globally unique identifiers that allow parties to
/// distinguish between different sessions. The "globally unique" property
/// of these identifiers forces parties to avoid any collisions between
/// different sessions and any kind of replay attack by associating messages,
/// parameters, proofs and commitments with their corresponding sessions.
///
/// # Discrepancies with the paper with respect to session identifiers:
///
/// Discrepancy (A): The paper distinguishes between the Session identifiers
/// (sid) which are created from shared parameters in the protocol at the
/// beginning of key generation and the Sub-Session identifiers (ssid) that are
/// created from sid and other post key generation shared parameters for the
/// purpose of pre/signing. The codebase does not make this kind of distinction
/// relying instead on a single type for all session identifiers. The
/// distinction between sessions and sub-sessions is inherently enforced by the
/// order of inputs and outputs to different stages in the protocol.
///
/// Discrepancy (B): The codebase  instantiates [`Identifier`]s in three
/// different ways: (1) as a session identifier for keygen, that are created at
/// the start of a key generation instance; (2) as a session identifier for
/// pre-signing, (3) as a session identifier for auxiliary information
/// generation sessions; The paper itself only distinguishes between sessions
/// and sub-sessions and combine (2) and (3).
///
/// Discrepancy (C): In the paper ssid is periodically refreshed with the
/// session key and auxiliary information. The codebase does not do that and
/// instead relies on the calling application to generate and refresh these
/// identifiers by randomly sampling a new and unique 32 bytes identifier using
/// `Identifier::random()`. This assumes that the participants initiating a
/// protocol run are honestly generating globally unique identifiers and
/// distributing them to the correct set of parties.
///
/// TODO: Discrepancy (C) needs to be further addressed by issue #218.
pub struct Identifier(u128);

impl Debug for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Id({})", hex::encode(&self.0.to_le_bytes()[..4]))
    }
}

impl Identifier {
    /// Produces a random [Identifier]
    #[instrument(skip_all)]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<u128>();
        trace!("Created new Session Identifier({random_bytes})");
        Self(random_bytes)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Id({})", hex::encode(&self.0.to_be_bytes()[..4]))
    }
}

/// Encodes the termination status and output (if any) of processing a message
/// as part of a protocol run.
#[derive(Debug)]
pub enum Output {
    /// The protocol did not complete.
    None,
    /// AuxInfo completed; output includes public key material for all
    /// participants and private key material for this participant.
    AuxInfo(Vec<AuxInfoPublic>, AuxInfoPrivate),
    /// KeyGen completed; output includes public key shares for all participants
    /// and a private key share for this participant.
    KeyGen(Vec<KeySharePublic>, KeySharePrivate),
    /// Presign completed; output includes a one-time-use presign record.
    Presign(PresignRecord),
    /// Local signing completed; output is this participant's share of the
    /// signature.
    Sign(SignatureShare),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::init_testing;
    use k256::ecdsa::signature::DigestVerifier;
    use rand::seq::IteratorRandom;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use tracing::debug;

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
    /// `presign_identifier` identifies a sub-session for pre-signing and
    /// signing.
    fn is_presigning_done(quorum: &[Participant], presign_identifier: Identifier) -> Result<bool> {
        for participant in quorum {
            if !participant.is_presigning_done(presign_identifier)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// `auxinfo_identifier` identifies a sub-session for auxiliary information
    /// generation.
    fn is_auxinfo_done(quorum: &[Participant], auxinfo_identifier: Identifier) -> Result<bool> {
        for participant in quorum {
            if !participant.is_auxinfo_done(auxinfo_identifier)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// `keygen_identifier` identifies a session that is initiated and defined
    /// by a call to KeyGen.
    fn is_keygen_done(quorum: &[Participant], keygen_identifier: Identifier) -> Result<bool> {
        for participant in quorum {
            if !participant.is_keygen_done(keygen_identifier)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut [Participant],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
    ) -> Result<()> {
        // Pick a random participant to process
        let participant = quorum.iter_mut().choose(rng).unwrap();

        let inbox = inboxes.get_mut(&participant.id).unwrap();
        if inbox.is_empty() {
            // No messages to process for this participant, so pick another participant
            return Ok(());
        }

        // Process a random message in the participant's inbox
        // This is done to simulate arbitrary message arrival ordering
        let index = rng.gen_range(0..inbox.len());
        let message = inbox.remove(index);
        debug!(
            "processing participant: {}, with message type: {:?}",
            &participant.id,
            &message.message_type(),
        );
        let (sid, output, messages) = participant.process_single_message(&message, rng)?;
        deliver_all(&messages, inboxes)?;

        // Check the protocol outputs are valid
        assert_eq!(message.id(), sid);
        let is_done_computes_correctly = match output {
            Output::AuxInfo(_, _) => participant.is_auxinfo_done(sid),
            Output::KeyGen(_, _) => participant.is_keygen_done(sid),
            Output::Presign(_) => participant.is_presigning_done(sid),
            Output::Sign(_) => Ok(true), // this doesn't have a check
            Output::None => {
                let auxinfo = participant.is_auxinfo_done(sid);
                let keygen = participant.is_keygen_done(sid);
                let presign = participant.is_presigning_done(sid);

                // The current behavior of these is weird -- they return Ok even if the `sid`
                // corresponds to a different protocol. Perhaps the "most
                // correct" version of this would check that exactly
                // one of these returns Ok(false), and the others return Err, but here we are:
                assert_eq!(auxinfo, Ok(false));
                assert_eq!(keygen, Ok(false));
                assert_eq!(presign, Ok(false));
                Ok(true)
            }
        };
        assert!(is_done_computes_correctly.is_ok() && is_done_computes_correctly.unwrap());

        Ok(())
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    fn test_run_protocol() -> Result<()> {
        let mut rng = init_testing();
        let mut quorum = Participant::new_quorum(3, &mut rng)?;
        let mut inboxes = HashMap::new();
        for participant in &quorum {
            let _ = inboxes.insert(participant.id, vec![]);
        }

        let auxinfo_identifier = Identifier::random(&mut rng);
        let keyshare_identifier = Identifier::random(&mut rng);
        let presign_identifier = Identifier::random(&mut rng);

        for participant in &quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_auxinfo_message(auxinfo_identifier));
        }

        while !is_auxinfo_done(&quorum, auxinfo_identifier)? {
            process_messages(&mut quorum, &mut inboxes, &mut rng)?;
        }

        for participant in &quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_keygen_message(keyshare_identifier));
        }
        while !is_keygen_done(&quorum, keyshare_identifier)? {
            process_messages(&mut quorum, &mut inboxes, &mut rng)?;
        }

        for participant in &mut quorum {
            let message = participant.initialize_presign_message(
                auxinfo_identifier,
                keyshare_identifier,
                presign_identifier,
            )?;
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(message);
        }
        while !is_presigning_done(&quorum, presign_identifier)? {
            process_messages(&mut quorum, &mut inboxes, &mut rng)?;
        }

        // Now, produce a valid signature
        let mut hasher = Sha256::new();
        hasher.update(b"some test message");

        let mut aggregator = SignatureShare::default();
        for participant in &mut quorum {
            let signature_share = participant.sign(presign_identifier, hasher.clone())?;
            aggregator = aggregator.chain(signature_share)?;
        }
        let signature = aggregator.finish()?;

        // Initialize all participants and get their public keyshares to construct the
        // final signature verification key
        let mut vk_point = CurvePoint::IDENTITY;
        for participant in &mut quorum {
            let X = participant.get_public_keyshare(keyshare_identifier)?;
            vk_point = CurvePoint(vk_point.0 + X.0);
        }
        let verification_key =
            k256::ecdsa::VerifyingKey::from_encoded_point(&vk_point.0.to_affine().into()).unwrap();

        // Moment of truth, does the signature verify?
        assert!(verification_key.verify_digest(hasher, &signature).is_ok());

        #[cfg(feature = "flame_it")]
        flame::dump_html(&mut std::fs::File::create("stats/flame-graph.html").unwrap()).unwrap();

        Ok(())
    }
}
