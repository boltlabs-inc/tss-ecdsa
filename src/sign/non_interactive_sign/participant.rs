// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module instantiates a [`SignParticipant`] which implements the
//! signing protocol.

use generic_array::{typenum::U32, GenericArray};
use k256::{
    ecdsa::{signature::DigestVerifier, VerifyingKey},
    elliptic_curve::{ops::Reduce, subtle::ConditionallySelectable, IsHigh},
    Scalar, U256,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};
use zeroize::Zeroize;

use crate::{
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePublic,
    local_storage::LocalStorage,
    messages::{Message, MessageType, SignMessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome},
    protocol::{ProtocolType, SharedContext},
    run_only_once,
    sign::{non_interactive_sign::share::SignatureShare, Signature},
    utils::CurvePoint,
    zkp::ProofContext,
    Identifier, ParticipantConfig, ParticipantIdentifier, PresignRecord, ProtocolParticipant,
};

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

/// Input for the signing protocol.
#[derive(Debug)]
pub struct Input {
    message_digest: Sha256,
    presign_record: PresignRecord,
    public_key_shares: Vec<KeySharePublic>,
}

impl Input {
    /// Construct a new input for signing.
    ///
    /// The `public_key_shares` should be the same ones used to generate the
    /// [`PresignRecord`].
    pub fn new(
        digest: Sha256,
        record: PresignRecord,
        public_key_shares: Vec<KeySharePublic>,
    ) -> Self {
        Self {
            message_digest: digest,
            presign_record: record,
            public_key_shares,
        }
    }

    /// Retrieve the presign record.
    pub(crate) fn presign_record(&self) -> &PresignRecord {
        &self.presign_record
    }

    /// Compute the digest. Note that this forces a clone of the `Sha256`
    /// object.
    pub(crate) fn digest(&self) -> GenericArray<u8, U32> {
        self.message_digest.clone().finalize()
    }

    pub(crate) fn public_key(&self) -> Result<k256::ecdsa::VerifyingKey> {
        // Add up all the key shares
        let public_key_point = self
            .public_key_shares
            .iter()
            .fold(CurvePoint::IDENTITY, |sum, share| sum + *share.as_ref());

        VerifyingKey::from_encoded_point(&public_key_point.0.to_affine().into()).map_err(|_| {
            error!("Keygen output does not produce a valid public key");
            CallerError::BadInput.into()
        })
    }
}

/// Protocol status for [`SignParticipant`].
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
            message_digest: p.input().digest().into(),
        }
    }
}

mod storage {
    use k256::Scalar;

    use crate::{local_storage::TypeTag, sign::non_interactive_sign::share::SignatureShare};

    pub(super) struct Share;
    impl TypeTag for Share {
        type Value = SignatureShare;
    }

    pub(super) struct XProj;
    impl TypeTag for XProj {
        type Value = Scalar;
    }
}

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
        info!(
            "Processing signing message of type {:?}",
            message.message_type()
        );

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
        }

        if !self.is_ready() && message.message_type() != Self::ready_type() {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        match message.message_type() {
            MessageType::Sign(SignMessageType::Ready) => self.handle_ready_message(rng, message),
            MessageType::Sign(SignMessageType::RoundOneShare) => self.handle_round_one_msg(message),
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
        let ready_outcome = self.process_ready_message(rng, message)?;

        // Generate round 1 messages
        let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, self.sid()))?;

        // If our generated share was the last one, complete the protocol.
        if self
            .storage
            .contains_for_all_ids::<storage::Share>(&self.all_participants())
        {
            let round_one_outcome = self.compute_output()?;
            ready_outcome
                .with_messages(round_one_messages)
                .consolidate(vec![round_one_outcome])
        } else {
            // Otherwise, just return the new messages
            Ok(ready_outcome.with_messages(round_one_messages))
        }
    }

    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        _sid: Identifier,
    ) -> Result<Vec<Message>> {
        let record = self.input.presign_record();

        // Interpret the message digest as an integer mod `q`. This matches the way that
        // the k256 library converts a digest to a scalar.
        let digest = <Scalar as Reduce<U256>>::from_be_bytes_reduced(self.input.digest());

        // Compute the x-projection of `R` from the `PresignRecord`
        let x_projection = record.x_projection()?;

        // Compute the share
        let share = SignatureShare::new(
            record.mask_share() * &digest + (x_projection * record.masked_key_share()),
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

    fn handle_round_one_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        // Make sure we're ready to process incoming messages
        if !self.is_ready() {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        // Save this signature share
        let share = SignatureShare::try_from(message)?;
        self.storage.store::<storage::Share>(message.from(), share);

        // If we haven't received shares from all parties, stop here
        if !self
            .storage
            .contains_for_all_ids::<storage::Share>(&self.all_participants())
        {
            return Ok(ProcessOutcome::Incomplete);
        }

        // Otherwise, continue on to run the `Output` step of the protocol
        self.compute_output()
    }

    /// Completes the "output" step of the protocol. This method assumes that
    /// you have received a share from every participant, including
    /// yourself!
    fn compute_output(&mut self) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        // Retrieve everyone's share and the x-projection we saved in round one
        // (This will fail if we're missing any shares)
        let shares = self
            .all_participants()
            .into_iter()
            .map(|pid| self.storage.remove::<storage::Share>(pid))
            .collect::<Result<Vec<_>>>()?;
        let x_projection = self.storage.remove::<storage::XProj>(self.id())?;

        // Sum up the signature shares and convert to BIP-0062 format (negating if the
        // sum is > group order /2)
        let mut sum = shares.into_iter().fold(Scalar::ZERO, |a, b| a + b);
        sum.conditional_assign(&sum.negate(), sum.is_high());

        let signature = Signature::try_from_scalars(x_projection, sum)?;

        // Verify signature
        self.input
            .public_key()?
            .verify_digest(self.input.message_digest.clone(), signature.as_ref())
            .map_err(|e| {
                error!("Failed to verify signature {:?}", e);
                InternalError::ProtocolError
            })?;

        // Output full signature
        self.status = Status::TerminatedSuccessfully;
        Ok(ProcessOutcome::Terminated(signature))
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use k256::{
        ecdsa::signature::{DigestVerifier, Verifier},
        elliptic_curve::{ops::Reduce, subtle::ConditionallySelectable, IsHigh},
        Scalar, U256,
    };
    use rand::{CryptoRng, Rng, RngCore};
    use sha2::{Digest, Sha256};
    use tracing::debug;

    use crate::{
        errors::Result,
        keygen,
        messages::{Message, MessageType},
        participant::ProcessOutcome,
        presign::PresignRecord,
        sign::{self, non_interactive_sign::participant::Status, Signature},
        utils::{bn_to_scalar, testing::init_testing},
        Identifier, ParticipantConfig, ProtocolParticipant,
    };

    use super::SignParticipant;

    /// Pick a random incoming message and have the correct participant process
    /// it.
    fn process_messages<'a, R: RngCore + CryptoRng>(
        quorum: &'a mut [SignParticipant],
        inbox: &mut Vec<Message>,
        rng: &mut R,
    ) -> Option<(&'a SignParticipant, ProcessOutcome<Signature>)> {
        // Pick a random message to process
        if inbox.is_empty() {
            return None;
        }
        let message = inbox.swap_remove(rng.gen_range(0..inbox.len()));
        let participant = quorum.iter_mut().find(|p| p.id() == message.to()).unwrap();

        debug!(
            "processing participant: {}, with message type: {:?} from {}",
            &message.to(),
            &message.message_type(),
            &message.from(),
        );

        let outcome = participant.process_message(rng, &message).unwrap();
        Some((participant, outcome))
    }

    #[test]
    fn signing_always_works() {
        for _ in 0..1000 {
            signing_produces_valid_signature().unwrap()
        }
    }

    /// This method is used for debugging. It "simulates" the non-distributed
    /// ECDSA signing algorithm by reconstructing the mask `k` and secret
    /// key fields from the presign records and keygen outputs,
    /// respectively, and using them to compute the signature.
    ///
    /// It can be used to check that the distributed signature is being computed
    /// correctly according to the presign record.
    fn compute_non_distributed_ecdsa(
        message: &[u8],
        records: &[PresignRecord],
        keygen_outputs: &[keygen::Output],
    ) -> k256::ecdsa::Signature {
        let k = records
            .iter()
            .map(|record| record.mask_share())
            .fold(Scalar::ZERO, |a, b| a + b);

        let secret_key = keygen_outputs
            .iter()
            .map(|output| bn_to_scalar(output.private_key_share().as_ref()).unwrap())
            .fold(Scalar::ZERO, |a, b| a + b);

        let r = records[0].x_projection().unwrap();

        let m = <Scalar as Reduce<U256>>::from_be_bytes_reduced(Sha256::digest(message));

        let mut s = k * (m + r * secret_key);
        s.conditional_assign(&s.negate(), s.is_high());

        let signature = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        // These checks fail when the overall thing fails
        let public_key = keygen_outputs[0].public_key().unwrap();

        assert!(public_key.verify(message, &signature).is_ok());
        assert!(public_key
            .verify_digest(Sha256::new().chain(message), &signature)
            .is_ok());
        signature
    }

    #[test]
    fn signing_produces_valid_signature() -> Result<()> {
        let quorum_size = 4;
        let rng = &mut init_testing();
        let sid = Identifier::random(rng);

        // Prepare prereqs for making SignParticipants. Assume all the simulations
        // are stable (e.g. keep config order)
        let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
        let keygen_outputs = keygen::Output::simulate_set(&configs, rng);
        let presign_records = PresignRecord::simulate_set(&keygen_outputs, rng);

        let message = b"the quick brown fox jumped over the lazy dog";
        let message_digest = sha2::Sha256::new().chain(message);

        // Save some things for later -- a signature constructucted from the records and
        // the public key
        let non_distributed_sig =
            compute_non_distributed_ecdsa(message, &presign_records, &keygen_outputs);
        let public_key = &keygen_outputs[0].public_key().unwrap();

        // Form signing inputs and participants
        let inputs = std::iter::zip(keygen_outputs, presign_records).map(|(keygen, record)| {
            sign::Input::new(
                message_digest.clone(),
                record,
                keygen.public_key_shares().to_vec(),
            )
        });
        let mut quorum =
            std::iter::zip(ParticipantConfig::random_quorum(quorum_size, rng)?, inputs)
                .map(|(config, input)| {
                    SignParticipant::new(sid, config.id(), config.other_ids().to_vec(), input)
                })
                .collect::<Result<Vec<_>>>()?;

        // Prepare caching of data (outputs and messages) for protocol execution
        let mut outputs = HashMap::with_capacity(quorum_size);

        let mut inbox = Vec::new();
        for participant in &quorum {
            let empty: [u8; 0] = [];
            inbox.push(Message::new(
                MessageType::Sign(crate::messages::SignMessageType::Ready),
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
            let (processor, outcome) = match process_messages(&mut quorum, &mut inbox, rng) {
                None => continue,
                Some(x) => x,
            };

            // Deliver messages and save outputs
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

            // Debug check -- did we process all the messages without finishing the
            // protocol?
            if inbox.is_empty()
                && !quorum
                    .iter()
                    .all(|p| *p.status() == Status::TerminatedSuccessfully)
            {
                panic!("we're stuck")
            }
        }

        // Everyone should have gotten an output
        assert_eq!(outputs.len(), quorum.len());
        let signatures = outputs.into_values().collect::<Vec<_>>();

        // Everyone should have gotten the same output. We don't use a hashset because
        // the underlying signature type doesn't derive `Hash`
        assert!(signatures
            .windows(2)
            .all(|signature| signature[0] == signature[1]));

        // Make sure the signature we got matches the non-distributed one
        let distributed_sig = &signatures[0];
        assert_eq!(distributed_sig.as_ref(), &non_distributed_sig);

        // Verify that we have a valid signature under the public key for the `message`
        assert!(public_key.verify(message, distributed_sig.as_ref()).is_ok());
        assert!(public_key
            .verify_digest(Sha256::new().chain(message), distributed_sig.as_ref())
            .is_ok());

        Ok(())
    }
}
