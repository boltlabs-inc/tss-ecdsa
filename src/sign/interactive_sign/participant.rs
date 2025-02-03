// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use rand::{CryptoRng, RngCore};
use sha3::{Digest, Keccak256};
use tracing::{error, info};

use crate::{
    auxinfo,
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    keygen::{self, KeySharePublic},
    message_queue::MessageQueue,
    messages::{Message, MessageType, SignMessageType},
    participant::{ProcessOutcome, Status},
    presign::{self, PresignParticipant, PresignRecord},
    protocol::ProtocolType,
    sign::{self, non_interactive_sign::participant::SignParticipant},
    Identifier, ParticipantIdentifier, ProtocolParticipant,
};

/// A participant that runs the interactive signing protocol in
/// Figure 3 of Canetti et al[^cite].
///
/// As described in the paper, this runs the [`presign`] phase,
/// followed by the [non-interactive signing](crate::sign::SignParticipant)
/// phase.
///
/// # Protocol input
/// The protocol takes several fields as input:
/// - a message digest, which is the hash of the message to be signed. This
///   library expects a 256-bit digest (e.g. produced by SHA3-256 (Keccak)).
/// - The [`Output`](crate::keygen::Output) of a [`keygen`] protocol execution
///   - A list of [public key shares](crate::keygen::KeySharePublic), one for
///     each participant (including this participant);
///   - A single [private key share](crate::keygen::KeySharePrivate) for this
///     participant; and
///   - A random value, agreed on by all participants.
/// - The [`Output`](crate::auxinfo::Output) of an [`auxinfo`] protocol
///   execution
///   - A list of [public auxiliary information](crate::auxinfo::AuxInfoPublic),
///     one for each participant (including this participant), and
///   - A single set of [private auxiliary
///     information](`crate::auxinfo::AuxInfoPrivate`) for this participant.
///
///
/// # Protocol output
/// Upon successful completion, the participant outputs a Signature.
/// The signature is on the message which was used to produce the provided
/// input message digest. It verifies under the public verification key
/// defined by the [keygen output](crate::keygen::Output).
///
///
/// [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
/// Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
/// with Identifiable Aborts. [EPrint archive,
/// 2021](https://eprint.iacr.org/2021/060.pdf).
#[derive(Debug)]
pub struct InteractiveSignParticipant<C: CurveTrait> {
    signing_material: SigningMaterial<C>,
    presigner: PresignParticipant<C>,
    signing_message_storage: MessageQueue,
}

/// Set of possible states for the signing material.
///
/// Either we have not yet started the signing protocol, so we are only saving
/// the input, or we are actively running signing.
#[derive(Debug)]
enum SigningMaterial<C: CurveTrait> {
    /// When we create the `signer`, we'll need to pass this input, plus the
    /// output of `presign`.
    PartialInput {
        // Boxed at the behest of compiler. This type is quite large.
        digest: Box<Keccak256>,
        public_keys: Vec<KeySharePublic<C>>,
    },
    Signer {
        // Boxed at the behest of compiler. This type is quite large.
        signer: Box<SignParticipant<C>>,
    },
}

impl<C: CurveTrait> SigningMaterial<C> {
    fn new_partial_input(digest: Keccak256, public_keys: Vec<KeySharePublic<C>>) -> Self {
        Self::PartialInput {
            digest: Box::new(digest),
            public_keys,
        }
    }

    /// Update from `PartialInput` to `Signer`.
    fn update(
        &mut self,
        record: PresignRecord<C>,
        id: ParticipantIdentifier,
        other_ids: Vec<ParticipantIdentifier>,
        sid: Identifier,
    ) -> Result<()> {
        // Take the original self and replace it with a placeholder value.
        let signing_material = std::mem::replace(
            self,
            SigningMaterial::new_partial_input(Default::default(), vec![]),
        );

        match signing_material {
            SigningMaterial::PartialInput {
                digest,
                public_keys,
            } => {
                // TODO: threhsold is not implemented yet for the interactive signing, must use
                // the same as the public keys size
                let threshold = public_keys.len();
                let signing_input =
                    sign::Input::new_from_digest(*digest, record, public_keys, threshold, None);
                // Note: this shouldn't throw an error because the only failure case should have
                // also been checked by the presign constructor, and computation
                // halted far before we reach this point.
                let signer = Box::new(SignParticipant::new(sid, id, other_ids, signing_input)?);
                *self = SigningMaterial::Signer { signer };
                Ok(())
            }
            original_state => {
                let _ = std::mem::replace(self, original_state);
                error!(
                    "State error: presigning just finished but we somehow already have a signer"
                );
                Err(InternalError::InternalInvariantFailed)?
            }
        }
    }

    fn as_mut_signer(&mut self) -> Result<&mut SignParticipant<C>> {
        match self {
            SigningMaterial::Signer { ref mut signer } => Ok(signer),
            _ => {
                error!("Tried to access the signer, but it doesn't exist yet");
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }
}

/// Input for the interactive signing protocol.
#[derive(Debug)]
pub struct Input<C> {
    message_digest: Keccak256,
    presign_input: presign::Input<C>,
}

impl<C: CurveTrait> Input<C> {
    /// Construct a new input for interactive signing from the outputs of the
    /// [`auxinfo`](crate::auxinfo::AuxInfoParticipant) and
    /// [`keygen`](crate::keygen::KeygenParticipant) protocols.
    ///
    /// The two output sets must have been generated by the same set of
    /// participants (with the same set of [`ParticipantIdentifier`]s) and
    /// private component of each output must correspond with the same
    /// participant.
    ///
    /// The message should be the raw bytes of the message to be signed; do not
    /// "pre-hash" the message. It is hashed here using SHA2-256.
    pub fn new(
        message: &[u8],
        keygen_output: keygen::Output<C>,
        auxinfo_output: auxinfo::Output,
    ) -> Result<Self> {
        let presign_input = presign::Input::new(auxinfo_output, keygen_output)?;
        let message_digest = Keccak256::new_with_prefix(message);
        Ok(Self {
            message_digest,
            presign_input,
        })
    }
}

impl<C: CurveTrait> ProtocolParticipant for InteractiveSignParticipant<C> {
    type Input = Input<C>;
    type Output = C::ECDSASignature;

    fn ready_type() -> MessageType {
        PresignParticipant::<C>::ready_type()
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::InteractiveSign
    }

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self> {
        let Input {
            message_digest,
            presign_input,
        } = input;

        let signing_material = SigningMaterial::new_partial_input(
            message_digest,
            presign_input.public_key_shares().to_vec(),
        );

        // Validation note: the presign participant will make sure the presign input and
        // public key shares are correctly formed (e.g. there's one per party)
        let presigner = PresignParticipant::new(sid, id, other_participant_ids, presign_input)?;

        Ok(Self {
            signing_material,
            presigner,
            signing_message_storage: MessageQueue::default(),
        })
    }

    fn id(&self) -> ParticipantIdentifier {
        // Note: signer should have the same participant ID
        self.presigner.id()
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        // Note: signer should have the same set of other IDs
        self.presigner.other_ids()
    }

    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "INTERACTIVE_SIGN: Player {}: received {:?} from {}",
            self.id(),
            message.message_type(),
            message.from()
        );

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
        }

        match message.message_type() {
            MessageType::Presign(_) => self.handle_presign_message(rng, message),
            MessageType::Sign(_) => self.handle_sign_message(rng, message),
            message_type => {
                error!(
                    "Incorrect MessageType routed to InteractiveSignParticipant. Got: {:?}",
                    message_type
                );
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    fn status(&self) -> &Status {
        // This method makes some assumptions about ordering for calling presign
        // and sign -- e.g. we will not pass a ready message to the `signer` until
        // the `presigner` is sucessfully completed.
        // Another option would be to maintain a status field and update it at
        // the appropriate points.
        if !self.presigner.status().is_ready() {
            return &Status::NotReady;
        }
        match &self.signing_material {
            SigningMaterial::PartialInput { .. } => &Status::RunningPresign,
            SigningMaterial::Signer { signer } => match signer.status() {
                Status::TerminatedSuccessfully => &Status::TerminatedSuccessfully,
                _ => &Status::RunningSign,
            },
        }
    }

    fn sid(&self) -> Identifier {
        // Note: signer should have the same sid
        self.presigner.sid()
    }
}

impl<C: CurveTrait> InteractiveSignParticipant<C> {
    fn handle_sign_message(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        match &mut self.signing_material {
            // If we haven't started signing yet, store the message for later
            SigningMaterial::PartialInput { .. } => {
                self.signing_message_storage.store(message.clone())?;
                Ok(ProcessOutcome::Incomplete)
            }

            // Otherwise, process the message
            SigningMaterial::Signer { signer } => signer.process_message(rng, message),
        }
    }

    fn handle_presign_message<'a, 'b>(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        message: &'a Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>>
    where
        C: 'a,
    {
        // Process message and get the components of the outcome
        let outcome = self.presigner.process_message(rng, message)?;
        let (maybe_record, presign_messages) = outcome.into_parts();

        // If presigning didn't finish, stop here.
        let record = match maybe_record {
            None => return Ok(ProcessOutcome::from(None, presign_messages)),
            Some(record) => record,
        };

        // Otherwise, presigning is done, so retrieve the input for sign and create the
        // signer
        self.signing_material
            .update(record, self.id(), self.other_ids().to_vec(), self.sid())?;

        // Then, form the ready message...
        let empty: [u8; 0] = [];
        let ready_message = Message::new(
            MessageType::Sign(SignMessageType::Ready),
            self.sid(),
            self.id(),
            self.id(),
            &empty,
        )?;

        // ...and process the ready message + any signing messages we already received.
        let signer = self.signing_material.as_mut_signer()?;
        let signing_outcomes = std::iter::once(ready_message)
            .chain(self.signing_message_storage.retrieve_all())
            .map(|message| signer.process_message(rng, &message))
            .collect::<Result<_>>()?;

        // Return any final presign messages + the outcomes from processing the sign
        // messages
        ProcessOutcome::collect_with_messages(signing_outcomes, presign_messages)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, ops::Deref};

    use k256::ecdsa::{signature::DigestVerifier, RecoveryId};
    use rand::{rngs::StdRng, Rng};
    use sha3::{Digest, Keccak256};
    use tracing::debug;

    use crate::{
        auxinfo,
        curve::{CurveTrait, TestCurve},
        errors::Result,
        keygen,
        messages::{Message, MessageType},
        participant::ProcessOutcome,
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ParticipantIdentifier, ProtocolParticipant,
    };

    use super::{Input, InteractiveSignParticipant, Status};

    #[test]
    fn input_from_valid_sources_is_valid() {
        let rng = &mut init_testing();
        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let keygen_output: keygen::output::Output<TestCurve> = keygen::Output::simulate(&pids, rng);
        let auxinfo_output = auxinfo::Output::simulate(&pids, rng);
        let message = b"greetings from the new world";
        assert!(Input::new(message, keygen_output, auxinfo_output).is_ok())
    }

    /// Pick a random incoming message and have the correct participant process
    /// it.
    fn process_messages<'a>(
        quorum: &'a mut [InteractiveSignParticipant<TestCurve>],
        inbox: &mut Vec<Message>,
        rng: &mut StdRng,
    ) -> (
        &'a InteractiveSignParticipant<TestCurve>,
        ProcessOutcome<<TestCurve as CurveTrait>::ECDSASignature>,
    ) {
        // Make sure test doesn't loop forever if we have a control flow problem
        if inbox.is_empty() {
            panic!("Protocol isn't done but there are no more messages!")
        }

        // Pick a random message to process
        let message = inbox.swap_remove(rng.gen_range(0..inbox.len()));
        let participant = quorum.iter_mut().find(|p| p.id() == message.to()).unwrap();

        debug!(
            "processing participant: {}, with message type: {:?} from {}",
            &message.to(),
            &message.message_type(),
            &message.from(),
        );

        let outcome = participant.process_message(rng, &message).unwrap();
        (participant, outcome)
    }

    #[test]
    #[ignore]
    fn interactive_signing_produces_valid_signature() -> Result<()> {
        let quorum_size = 4;
        let rng = &mut init_testing();
        let sid = Identifier::random(rng);

        // Prepare prereqs for making SignParticipants. Assume all the simulations
        // are stable (e.g. keep config order)
        let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
        let keygen_outputs = keygen::Output::simulate_set(&configs, rng);
        let auxinfo_outputs = auxinfo::Output::simulate_set(&configs, rng);

        let message = b"in an old house in paris all covered in vines lived 12 little girls";
        let digest = Keccak256::new_with_prefix(message);

        // Save the public key for later
        let public_key = &keygen_outputs[0].public_key().unwrap();

        let inputs = std::iter::zip(keygen_outputs, auxinfo_outputs)
            .map(|(keygen_output, auxinfo_output)| {
                Input::new(message, keygen_output, auxinfo_output)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut quorum = std::iter::zip(configs, inputs)
            .map(|(config, input)| {
                InteractiveSignParticipant::new(
                    sid,
                    config.id(),
                    config.other_ids().to_vec(),
                    input,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        // Prepare caching of data (outputs and messages) for protocol execution
        let mut outputs = HashMap::with_capacity(quorum_size);

        let mut inbox = Vec::new();
        for participant in &quorum {
            let empty: [u8; 0] = [];
            inbox.push(Message::new(
                MessageType::Presign(crate::messages::PresignMessageType::Ready),
                sid,
                participant.id(),
                participant.id(),
                &empty,
            )?);
        }

        // Run protocol until all participants report that they're done
        while !quorum
            .iter()
            .all(|participant| *participant.status() == Status::TerminatedSuccessfully)
        {
            // Pick a random message to prcoess
            let (processor, outcome) = process_messages(&mut quorum, &mut inbox, rng);

            // Deliver any generated messages and save outputs
            match outcome {
                ProcessOutcome::Incomplete => {}
                ProcessOutcome::Processed(messages) => inbox.extend(messages),
                ProcessOutcome::Terminated(output) => {
                    assert!(outputs.insert(processor.id(), output).is_none())
                }
                ProcessOutcome::TerminatedForThisParticipant(output, messages) => {
                    inbox.extend(messages);
                    assert!(outputs.insert(processor.id(), output).is_none());
                }
            }
        }

        // Everyone should have gotten a signature as output
        assert_eq!(outputs.len(), quorum.len());
        let signatures = outputs.into_values().collect::<Vec<_>>();

        // Everyone should have gotten the same signature. We don't use a hashset
        // because the underlying signature type doesn't derive `Hash`
        assert!(signatures
            .windows(2)
            .all(|signature| signature[0] == signature[1]));

        let distributed_sig = &signatures[0];

        // Verify that we have a valid signature under the public key for the `message`
        assert!(public_key
            .verify_digest(digest.clone(), distributed_sig.deref())
            .is_ok());

        // Check we are able to create a recoverable signature.
        let recovery_id = distributed_sig
            .recovery_id(message, public_key)
            .expect("Recovery ID failed");

        // Re-derive the public key from the recoverable ID and ensure it matches the
        // original public key.
        let recovered_pk = <TestCurve as CurveTrait>::VerifyingKey::recover_from_digest(
            digest,
            distributed_sig,
            RecoveryId::from_byte(recovery_id).expect("Invalid recovery ID"),
        )
        .unwrap();

        assert_eq!(
            recovered_pk, *public_key,
            "Recovered public key does not match original one."
        );

        Ok(())
    }
}
