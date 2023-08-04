// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module instantiates a [`SignParticipant`] which implements the
//! signing protocol.

use k256::{ecdsa::VerifyingKey, Scalar};
use rand::{CryptoRng, RngCore};
use tracing::{error, info, warn};

use crate::{
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePublic,
    local_storage::LocalStorage,
    messages::{Message, MessageType, SignMessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome},
    protocol::{ProtocolType, SharedContext},
    run_only_once,
    sign::share::{Signature, SignatureShare},
    utils::{bn_to_scalar, CurvePoint},
    zkp::ProofContext,
    Identifier, ParticipantConfig, ParticipantIdentifier, PresignRecord, ProtocolParticipant,
};
use libpaillier::unknown_order::BigNumber;
use zeroize::Zeroize;

/// A participant that runs the signing protocol in Figure 8 of Canetti et
/// al[^cite].
///
/// Note that this only runs Figure 8. By itself, this corresponds to the
/// non-interactive signing protocol; it expects a
/// [`PresignRecord`](crate::PresignRecord) as input. It could be
/// used as a component to execute the interactive signing protocol, but this is
/// not yet implemented.
///
///
/// # Protocol input
/// The protocol takes two fields as input:
/// - a message digest, which is the hash of the message to be signed. This
///   library expects a 256-bit digest (e.g. produced by SHA3-256 (Keccak)).
/// - a [`PresignRecord`]. This must be fresh (never used for any other
///   execution of the threshold ECDSA protocol, even a failed run) and must
///   have been generated using the private share of the key under which the
///   caller desires a signature.
///
///
/// # Protocol output
/// Upon successful completion, the participant outputs a [`Signature`].
/// The signature is on the message which was used to produce the provided
///   input message digest. It verifies under the public verification key
/// corresponding to the private signing key used to produce the input
///   [`PresignRecord`].
///
/// # 🔒 Storage requirement
/// The [`PresignRecord`] provided as input must be discarded; no copies should
/// remain after use.
///
/// [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
/// Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
/// with Identifiable Aborts. [EPrint archive,
/// 2021](https://eprint.iacr.org/2021/060.pdf).

pub struct SignParticipant {
    sid: Identifier,
    storage: LocalStorage,
    input: Input,
    config: ParticipantConfig,
    status: Status,
}

/// Input for a [`SignParticipant`].
#[allow(unused)]
#[derive(Debug)]
pub struct Input {
    message_digest: Box<[u8; 32]>,
    presign_record: PresignRecord,
    public_key_shares: Vec<KeySharePublic>,
}

impl Input {
    /// Construct a new input for signing.
    ///
    /// The `public_key_shares` should be the same ones used to generate the
    /// [`PresignRecord`].
    pub fn new(
        digest: Box<[u8; 32]>,
        record: PresignRecord,
        public_key_shares: Vec<KeySharePublic>,
    ) -> Self {
        Self {
            message_digest: digest,
            presign_record: record,
            public_key_shares,
        }
    }

    pub(crate) fn presign_record(&self) -> &PresignRecord {
        &self.presign_record
    }

    pub(crate) fn digest(&self) -> &[u8] {
        self.message_digest.as_slice()
    }

    pub(crate) fn public_key(&self) -> Result<k256::ecdsa::VerifyingKey> {
        // Add up all the key shares
        let public_key_point = self
            .public_key_shares
            .iter()
            .fold(CurvePoint::IDENTITY, |sum, share| sum + *share.as_ref());

        VerifyingKey::from_encoded_point(&public_key_point.0.to_affine().into()).map_err(|_| {
            error!("Keygen output does not produce a valid public key.");
            InternalError::InternalInvariantFailed
        })
    }
}

/// Protocol status for [`SignParticipant`].
#[allow(unused)]
#[derive(Debug, PartialEq)]
pub enum Status {
    /// Participant is created but has not received a ready message from self.
    NotReady,
    /// Participant received a ready message and is executing the protocol.
    Initialized,
    /// Participant finished the protocol.
    TerminatedSuccessfully,
}

/// Context for fiat-Shamir proofs generated in the non-interactive signing
/// protocol.
///
/// Note that this is only used in the case of identifiable abort, which is not
/// yet implemented. A correct execution of signing does not involve any ZK
/// proofs.
pub(crate) struct SignContext {
    shared_context: SharedContext,
    message_digest: [u8; 32],
}

impl ProofContext for SignContext {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok([
            self.shared_context.as_bytes()?,
            self.message_digest.to_vec(),
        ]
        .concat())
    }
}

impl SignContext {
    /// Build a [`SignContext`] from a [`SignParticipant`].
    pub(crate) fn collect(p: &SignParticipant) -> Self {
        Self {
            shared_context: SharedContext::collect(p),
            message_digest: *p.input().message_digest,
        }
    }
}

mod storage {
    use k256::Scalar;

    use crate::{local_storage::TypeTag, sign::share::SignatureShare};

    pub(super) struct Share;
    impl TypeTag for Share {
        type Value = SignatureShare;
    }

    pub(super) struct XProj;
    impl TypeTag for XProj {
        type Value = Scalar;
    }
}

#[allow(unused)]
impl ProtocolParticipant for SignParticipant {
    type Input = Input;
    type Output = Signature;
    type Status = Status;

    fn ready_type() -> MessageType {
        MessageType::Sign(SignMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        todo!()
    }

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        let config = ParticipantConfig::new(id, &other_participant_ids)?;
        Ok(Self {
            sid,
            config,
            input,
            storage: Default::default(),
            status: Status::NotReady,
        })
    }

    fn id(&self) -> ParticipantIdentifier {
        self.config.id()
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        self.config.other_ids()
    }

    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing signing message.");

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
        }

        if !self.is_ready() && message.message_type() != Self::ready_type() {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        match message.message_type() {
            MessageType::Sign(SignMessageType::Ready) => self.handle_ready_message(rng, message),
            MessageType::Sign(SignMessageType::RoundOneShare) => {
                self.handle_round_one_msg(rng, message)
            }
            message_type => {
                error!(
                    "Invalid MessageType passed to SignParticipant. Got: {:?}",
                    message_type
                );
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    fn status(&self) -> &Self::Status {
        &self.status
    }

    fn sid(&self) -> Identifier {
        self.sid
    }

    fn input(&self) -> &Self::Input {
        &self.input
    }

    fn is_ready(&self) -> bool {
        self.status != Status::NotReady
    }
}

impl InnerProtocolParticipant for SignParticipant {
    type Context = SignContext;

    fn retrieve_context(&self) -> Self::Context {
        SignContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.storage
    }

    fn set_ready(&mut self) {
        if self.status == Status::NotReady {
            self.status = Status::Initialized;
        } else {
            warn!(
                "Something is strange in the status updates for signing.
                 Tried to update from `NotReady` to `Initialized`, but status was {:?}",
                self.status
            )
        }
    }
}

impl SignParticipant {
    /// Handle a "Ready" message from ourselves.
    ///
    /// Once a "Ready" message has been received, continue to generate the round
    /// one message.
    fn handle_ready_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling sign ready message.");

        let ready_outcome = self.process_ready_message(rng, message)?;

        // Generate round 1 messages (note: the run_only_once! should be unnecessary
        // now)
        let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, self.sid()))?;

        // Process any stashed round 1 messages from other parties
        // `process_ready_message` also does this, but because of our "readiness check"
        // in `handle_round_one_msgs`, it'll just re-stash anything we've
        // received until after we run `gen_round_one_msgs`, so we re-process
        // them here
        let round_one_outcomes = self
            .fetch_messages(MessageType::Sign(SignMessageType::RoundOneShare))?
            .iter()
            .map(|message| self.process_message(rng, message))
            .collect::<Result<_>>()?;

        ready_outcome
            .with_messages(round_one_messages)
            .consolidate(round_one_outcomes)
    }

    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        _sid: Identifier,
    ) -> Result<Vec<Message>> {
        let record = &self.input.presign_record();

        // Interpret the message digest as an integer mod `q`
        // Note: The `from_slice` method doesn't document the fact that it reads numbers
        // in big-endian
        let digest = bn_to_scalar(&BigNumber::from_slice(self.input.digest()))?;
        //TODO: try to simplify / clean up bn_to_scalar method

        // Compute the x-projection of `R` from the `PresignRecord`
        let x_projection = record.x_projection()?;

        // Compute the share
        let share = SignatureShare::new(
            record.mask_share() * &digest + x_projection * record.masked_key_share(),
        );

        // Erase the presign record
        self.input.presign_record.zeroize();

        // Save pieces for our own use later
        self.storage
            .store::<storage::Share>(self.id(), share.clone());
        self.storage
            .store::<storage::XProj>(self.id(), x_projection);

        // Form output messages
        self.message_for_other_participants(
            MessageType::Sign(SignMessageType::RoundOneShare),
            share,
        )
    }

    #[allow(unused)]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        // Make sure we're ready to process incoming messages
        if !self.is_ready() {
            self.stash_message(message);
            return Ok(ProcessOutcome::Incomplete);
        }

        // Save this signature share
        let share = SignatureShare::try_from(message)?;
        self.storage.store::<storage::Share>(message.from(), share);

        // If we haven't received shares from all parties, stop here
        let all_participants = self.all_participants();
        if !self
            .storage
            .contains_for_all_ids::<storage::Share>(&all_participants)
        {
            return Ok(ProcessOutcome::Incomplete);
        }

        // Otherwise, get everyone's share and the x-projection we saved in round one
        let shares = all_participants
            .into_iter()
            .map(|pid| self.storage.remove::<storage::Share>(pid))
            .collect::<Result<Vec<_>>>()?;
        let x_projection = self.storage.remove::<storage::XProj>(self.id())?;

        // Compute full signature
        let sum = shares.into_iter().fold(Scalar::ZERO, |a, b| a + b);

        let signature = Signature::try_from_scalars(x_projection, sum)?;

        // TODO: Verify signature
        // We currently can't verify the signature because we only have the digest
        // encoded as bytes. The k256 library v10.4 provides two APIs: one that
        // takes a `Digest` and one that takes the original message. The latest
        // version (13.1 at time of writing) provides a `hazmat` method
        // to verify from the digest-as-bytes; we have to be very sure that it's
        // actually a hash digest to avoid security issues.

        // Output full signature
        self.status = Status::TerminatedSuccessfully;
        Ok(ProcessOutcome::Terminated(signature))
    }
}
