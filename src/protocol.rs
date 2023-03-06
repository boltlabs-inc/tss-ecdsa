// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main protocol that is executed through a [Participant]

use crate::{
    auxinfo::participant::{AuxInfoParticipant, StorageType as AuxInfoStorageType},
    errors::{InternalError, Result},
    keygen::{keyshare::KeySharePublic, participant::KeygenParticipant},
    messages::{AuxinfoMessageType, KeygenMessageType, MessageType},
    participant::ProtocolParticipant,
    presign::{
        participant::{PresignParticipant, StorageType as PresignStorageType},
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
use tracing::{info, instrument, trace};

/////////////////////
// Participant API //
/////////////////////

/// Each participant has an inbox which can contain messages.
#[derive(Serialize, Deserialize, Clone, Debug)]
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

    /// Pulls the first message from the participant's inbox, and then
    /// potentially outputs a bunch of messages that need to be delivered to
    /// other participants' inboxes.
    #[cfg_attr(feature = "flame_it", flame)]
    #[instrument(skip_all, err(Debug))]
    pub fn process_single_message<R: RngCore + CryptoRng>(
        &mut self,
        message: &Message,
        rng: &mut R,
    ) -> Result<Vec<Message>> {
        info!("Processing single message.");

        if message.to() != self.id {
            return Err(InternalError::WrongMessageRecipient);
        }
        match message.message_type() {
            MessageType::Auxinfo(_) => {
                let outcome = self.auxinfo_participant.process_message(
                    rng,
                    message,
                    &mut self.main_storage,
                )?;
                Ok(outcome.into_messages())
            }
            MessageType::Keygen(_) => {
                let outcome = self.keygen_participant.process_message(
                    rng,
                    message,
                    &mut self.main_storage,
                )?;
                Ok(outcome.into_messages())
            }
            MessageType::Presign(_) => {
                // Send presign message and existing storage containing auxinfo and
                // keyshare values that presign needs to operate
                let outcome = self.presign_participant.process_message(
                    rng,
                    message,
                    &mut self.main_storage,
                )?;

                let (output, messages) = outcome.into_parts();

                if let Some(presign_record) = output {
                    self.main_storage.store(
                        PresignStorageType::Record,
                        message.id(),
                        self.id,
                        &presign_record,
                    )?;
                }

                Ok(messages)
            }
            _ => Err(InternalError::MisroutedMessage),
        }
    }

    /// Produces a message to signal to this participant that auxinfo generation
    /// is ready for the specified identifier
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
        for participant in self.other_participant_ids.clone() {
            fetch.push((AuxInfoStorageType::Public, auxinfo_identifier, participant));
        }
        fetch.push((AuxInfoStorageType::Public, auxinfo_identifier, self.id));
        fetch.push((AuxInfoStorageType::Private, auxinfo_identifier, self.id));

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
            PresignStorageType::Record,
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
    #[instrument(skip_all, err(Debug))]
    pub fn sign(
        &mut self,
        presign_identifier: Identifier,
        digest: sha2::Sha256,
    ) -> Result<SignatureShare> {
        info!("Issuing signature with presign record.");

        let presign_record: PresignRecord =
            self.main_storage
                .retrieve(PresignStorageType::Record, presign_identifier, self.id)?;
        let (r, s) = presign_record.sign(digest)?;
        let ret = SignatureShare { r: Some(r), s };

        // Clear the presign record after being used once
        let _ =
            self.main_storage
                .delete(PresignStorageType::Record, presign_identifier, self.id)?;
        Ok(ret)
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
            // Reason: Input share was not initialized
            (_, None) => Err(InternalError::InternalInvariantFailed),
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
pub struct ParticipantIdentifier(Identifier);

impl ParticipantIdentifier {
    /// Generates a random [ParticipantIdentifier]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        ParticipantIdentifier(Identifier::random(rng))
    }
}

impl std::fmt::Display for ParticipantIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ParticipantId({})",
            hex::encode(&self.0 .0.to_be_bytes()[..4])
        )
    }
}

/// A generic identifier
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        trace!("Created new Identifier({random_bytes})");
        Self(random_bytes)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Id({})", hex::encode(&self.0.to_be_bytes()[..4]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::DigestVerifier;
    use rand::seq::IteratorRandom;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use test_log::test;
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

    fn is_presigning_done(quorum: &[Participant], presign_identifier: Identifier) -> Result<bool> {
        for participant in quorum {
            if !participant.is_presigning_done(presign_identifier)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn is_auxinfo_done(quorum: &[Participant], auxinfo_identifier: Identifier) -> Result<bool> {
        for participant in quorum {
            if !participant.is_auxinfo_done(auxinfo_identifier)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

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
        let messages = participant.process_single_message(&message, rng)?;
        deliver_all(&messages, inboxes)?;

        Ok(())
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    fn test_run_protocol() -> Result<()> {
        let mut rng = crate::utils::get_test_rng();
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
