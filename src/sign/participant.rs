// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module instantiates a [`SignParticipant`] which implements the
//! signing protocol.

use rand::{CryptoRng, RngCore};
use tracing::{error, info, warn};

use crate::{
    errors::{CallerError, InternalError, Result},
    local_storage::LocalStorage,
    messages::{Message, MessageType, SignMessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome},
    protocol::{ProtocolType, SharedContext},
    run_only_once,
    zkp::ProofContext,
    Identifier, ParticipantConfig, ParticipantIdentifier, PresignRecord, ProtocolParticipant,
};

use super::share::Signature;

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
}

impl Input {
    #[allow(unused)]
    pub(crate) fn presign_record(&self) -> &PresignRecord {
        &self.presign_record
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
    use crate::{local_storage::TypeTag, sign::share::SignatureShare};

    pub(super) struct Share;
    impl TypeTag for Share {
        type Value = SignatureShare;
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
        let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, message.id()))?;
        // extend the output with round one messages (if they hadn't already been
        // generated)
        Ok(ready_outcome.with_messages(round_one_messages))
    }

    #[allow(unused)]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        // Compute the x-projection of `R` from the `PresignRecord`

        // Compute the share

        // Form output messages
        todo!()
    }

    #[allow(unused)]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        // Stash signature share

        // If we've received all messages...

        // Compute full signature

        // Verify signature (how? -- might need to add input from auxinfo + keygen)

        // Output full signature (TODO: add type)

        todo!()
    }
}
