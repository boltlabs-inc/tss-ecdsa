// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use tracing::{error, info};

use crate::{
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePublic,
    message_queue::MessageQueue,
    messages::{Message, MessageType, SignMessageType},
    participant::{ProcessOutcome, Status},
    presign::{self, PresignParticipant},
    protocol::ProtocolType,
    sign::{self, non_interactive_sign::participant::SignParticipant, Signature},
    Identifier, ParticipantIdentifier, ProtocolParticipant,
};

/// A participant that runs the interactive signing protocol in
/// Figure 3 of Canetti et al[^cite].
///
/// As described in the paper, this runs the [`presign`](crate::presign) phase,
/// followed by the [non-interactive signing](crate::sign::SignParticipant)
/// phase.
///
/// # Protocol input
/// The protocol takes several fields as input:
/// - a message digest, which is the hash of the message to be signed. This
///   library expects a 256-bit digest (e.g. produced by SHA3-256 (Keccak)).
/// - The [`Output`](crate::keygen::Output) of a [`keygen`](crate::keygen)
///   protocol execution
///   - A list of [public key shares](crate::keygen::KeySharePublic), one for
///     each participant (including this participant);
///   - A single [private key share](crate::keygen::KeySharePrivate) for this
///     participant; and
///   - A random value, agreed on by all participants.
/// - The [`Output`](crate::auxinfo::Output) of an [`auxinfo`](crate::auxinfo)
///   protocol execution
///   - A list of [public auxiliary information](crate::auxinfo::AuxInfoPublic),
///     one for each participant (including this participant), and
///   - A single set of [private auxiliary
///     information](`crate::auxinfo::AuxInfoPrivate`) for this participant.
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
#[derive(Debug)]
pub struct InteractiveSignParticipant {
    /// When we create the `signer`, we'll need to pass this input, plus the
    /// output of `presign`.
    partial_signing_input: (Sha256, Vec<KeySharePublic>),
    presigner: PresignParticipant,
    signer: Option<SignParticipant>,
    signing_message_storage: MessageQueue,
}

/// Input for the interactive signing protocol.
#[derive(Debug)]
#[allow(unused)]
pub struct Input {
    message_digest: Sha256,
    presign_input: presign::Input,
}

impl ProtocolParticipant for InteractiveSignParticipant {
    type Input = Input;
    type Output = Signature;

    fn ready_type() -> MessageType {
        PresignParticipant::ready_type()
    }

    fn protocol_type() -> ProtocolType {
        todo!()
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
        let partial_signing_input = (message_digest, presign_input.public_key_shares().to_vec());

        // Validation note: the presign participant will make sure the presign input and
        // public key shares are correctly formed (e.g. there's one per party)
        let presigner = PresignParticipant::new(sid, id, other_participant_ids, presign_input)?;

        Ok(Self {
            partial_signing_input,
            presigner,
            signer: None,
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
        // the appropriate poitns.
        if !self.presigner.status().is_ready() {
            return &Status::NotReady;
        }
        match &self.signer {
            None => &Status::RunningPresign,
            Some(signer) => match signer.status() {
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

impl InteractiveSignParticipant {
    fn handle_sign_message(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        match &mut self.signer {
            // If we haven't started signing yet, store the message for later
            None => {
                self.signing_message_storage.store(message.clone())?;
                Ok(ProcessOutcome::Incomplete)
            }

            // Otherwise, process the message
            Some(signer) => signer.process_message(rng, message),
        }
    }

    fn handle_presign_message(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        // Process message and get the components of the outcome
        let outcome = self.presigner.process_message(rng, message)?;
        let (maybe_record, presign_messages) = outcome.into_parts();

        // State check -- make sure we haven't already gotten a signer
        if self.signer.is_some() {
            error!("Presign is still running but we already created a signer, somehow");
            Err(InternalError::InternalInvariantFailed)?
        }

        // If presigning didn't finish, stop here.
        let record = match maybe_record {
            None => return Ok(ProcessOutcome::from(None, presign_messages)),
            Some(record) => record,
        };

        // Otherwise, presigning is done, so create the signer...
        let (digest, public_key_shares) = self.partial_signing_input.clone();
        let signing_input = sign::Input::new(digest, record, public_key_shares);
        let mut signer = SignParticipant::new(
            self.sid(),
            self.id(),
            self.other_ids().to_vec(),
            signing_input,
        )?;

        // ...form the ready message...
        let empty: [u8; 0] = [];
        let ready_message = Message::new(
            MessageType::Sign(SignMessageType::Ready),
            self.sid(),
            self.id(),
            self.id(),
            &empty,
        )?;

        // ...and process the ready message + any signing messages we already received.
        let signing_outcomes = std::iter::once(ready_message)
            .chain(self.signing_message_storage.retrieve_all())
            .map(|message| signer.process_message(rng, &message))
            .collect::<Result<_>>()?;

        self.signer = Some(signer);

        // Return any final presign messages + the outcomes from processing the sign
        // messages
        ProcessOutcome::collect_with_messages(signing_outcomes, presign_messages)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use k256::ecdsa::signature::{DigestVerifier, Verifier};
    use rand::{rngs::StdRng, Rng};
    use sha2::{Digest, Sha256};
    use tracing::debug;

    use crate::{
        auxinfo,
        errors::Result,
        keygen,
        messages::{Message, MessageType},
        participant::ProcessOutcome,
        presign,
        sign::Signature,
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ProtocolParticipant,
    };

    use super::{Input, InteractiveSignParticipant, Status};

    /// Pick a random incoming message and have the correct participant process
    /// it.
    fn process_messages<'a>(
        quorum: &'a mut [InteractiveSignParticipant],
        inbox: &mut Vec<Message>,
        rng: &mut StdRng,
    ) -> (&'a InteractiveSignParticipant, ProcessOutcome<Signature>) {
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
        let message_digest = sha2::Sha256::new().chain_update(message);

        // Save the public key for later
        let public_key = &keygen_outputs[0].public_key().unwrap();

        let inputs = std::iter::zip(keygen_outputs, auxinfo_outputs)
            .map(|(keygen_output, auxinfo_output)| {
                Ok(Input {
                    message_digest: message_digest.clone(),
                    presign_input: presign::Input::new(auxinfo_output, keygen_output)?,
                })
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
        assert!(public_key.verify(message, distributed_sig.as_ref()).is_ok());
        assert!(public_key
            .verify_digest(
                Sha256::new().chain_update(message),
                distributed_sig.as_ref()
            )
            .is_ok());

        Ok(())
    }
}
