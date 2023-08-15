use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::{
    errors::Result,
    messages::{Message, MessageType},
    participant::ProcessOutcome,
    presign::{self, PresignParticipant},
    protocol::ProtocolType,
    sign::{
        non_interactive_sign::{self, participant::SignParticipant},
        Signature,
    },
    Identifier, ParticipantIdentifier, ProtocolParticipant,
};

/// A participant that runs the interactive signing protocol in
/// Figure 3 of Canetti et al[^cite].
///
/// As described in the paper, this runs the [`presign`](crate::presign) phase,
/// followed by the [non-interactive signing](crate::sign::non_interactive_sign)
/// phase.
///
/// # Protocol input
/// The protocol takes several fields as input:
/// - a message digest, which is the hash of the message to be signed. This
///   library expects a 256-bit digest (e.g. produced by SHA3-256 (Keccak)).
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
///
/// # Protocol output
/// Upon successful completion, the participant outputs a [`Signature`].
/// The signature is on the message which was used to produce the provided
/// input message digest. It verifies under the public verification key
/// defined by the [keygen output](crate::keygen::Output).
///
///
/// [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
/// Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
/// with Identifiable Aborts. [EPrint archive,
/// 2021](https://eprint.iacr.org/2021/060.pdf).
pub struct InteractiveSignParticipant {
    input: Input,
    presigner: PresignParticipant,
    signer: SignParticipant,
}

#[derive(Debug)]
#[allow(unused)]
pub struct Input {
    message_digest: Sha256,
    presign_input: presign::Input,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// Participant is created but has not received a ready message from self.
    NotReady,
    /// Participant received a ready message and is running presign.
    RunningPresign,
    /// Participant completed presign and is running sign.
    RunningSign,
    /// Participant completed signing and output a signature.
    TerminatedSuccessfully,
}

impl ProtocolParticipant for InteractiveSignParticipant {
    type Input = Input;
    type Output = Signature;

    type Status = Status;

    /// Get the type of a "ready" message, signalling that a participant
    /// is ready to begin protocol execution.
    fn ready_type() -> MessageType {
        PresignParticipant::ready_type()
    }

    /// Define which protocol this implements.
    fn protocol_type() -> ProtocolType {
        todo!()
    }

    #[allow(unused)]
    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self> {
        todo!()
    }

    /// Return the participant id
    fn id(&self) -> ParticipantIdentifier {
        // Note: both participants must have the same participant ID
        self.presigner.id()
    }

    /// Return other Participant ids apart from the current one
    fn other_ids(&self) -> &[ParticipantIdentifier] {
        // Note: both participants must have the same set of other IDs
        self.presigner.other_ids()
    }

    #[allow(unused)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        todo!()
    }

    /// The status of the protocol execution.
    fn status(&self) -> &Self::Status {
        if !self.presigner.is_ready() {
            return &Status::NotReady;
        }
        if !self.signer.is_ready() {
            return &Status::RunningPresign;
        }
        if self.signer.status()
            != &non_interactive_sign::participant::Status::TerminatedSuccessfully
        {
            &Status::RunningSign
        } else {
            &Status::TerminatedSuccessfully
        }
    }

    /// The session identifier for the current session
    fn sid(&self) -> Identifier {
        self.presigner.sid()
    }

    /// The input of the current session
    fn input(&self) -> &Self::Input {
        &self.input
    }

    /// Returns whether or not the Participant is Ready
    fn is_ready(&self) -> bool {
        self.status() != &Status::NotReady
    }
}
