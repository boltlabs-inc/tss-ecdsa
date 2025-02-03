// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::{collections::HashSet, fmt::Debug};

use generic_array::{typenum::U32, GenericArray};
use rand::{CryptoRng, RngCore};
use sha3::{Digest, Keccak256};
use tracing::{error, info};
use zeroize::Zeroize;

use crate::{
    curve::{CurveTrait, ScalarTrait, SignatureTrait, VerifyingKeyTrait},
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePublic,
    local_storage::LocalStorage,
    messages::{Message, MessageType, SignMessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome, Status},
    protocol::{ProtocolType, SharedContext},
    run_only_once,
    sign::non_interactive_sign::share::SignatureShare,
    zkp::ProofContext,
    Identifier, ParticipantConfig, ParticipantIdentifier, PresignRecord, ProtocolParticipant,
};

/// A participant that runs the non-interactive signing protocol.
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
/// Upon successful completion, the participant outputs a Signature.
/// The signature is on the message which was used to produce the provided
///   input message digest. It verifies under the public verification key
/// corresponding to the private signing key used to produce the input
///   [`PresignRecord`].
///
/// # 🔒 Storage requirement
/// The [`PresignRecord`] provided as input must be discarded; no copies should
/// remain after use.
#[derive(Debug)]
pub struct SignParticipant<C: CurveTrait> {
    sid: Identifier,
    storage: LocalStorage,
    input: Input<C>,
    config: ParticipantConfig,
    status: Status,
}

/// Input for the non-interactive signing protocol.
#[derive(Debug)]
pub struct Input<C: CurveTrait> {
    digest: Keccak256,
    presign_record: PresignRecord<C>,
    public_key_shares: Vec<KeySharePublic<C>>,
    threshold: usize,
    shift: Option<C::Scalar>,
}

impl<C: CurveTrait> Input<C> {
    /// Construct a new input for signing.
    ///
    /// The `public_key_shares` should be the same ones used to generate the
    /// [`PresignRecord`].
    pub fn new(
        message: &[u8],
        record: PresignRecord<C>,
        public_key_shares: Vec<KeySharePublic<C>>,
        threshold: usize,
        shift: Option<C::Scalar>,
    ) -> Self {
        Self {
            digest: Keccak256::new_with_prefix(message),
            presign_record: record,
            public_key_shares,
            threshold,
            shift,
        }
    }

    /// Internal-only method to create an input from a pre-existing digest.
    ///
    /// This exists so that interactive signing can hash the message as soon as
    /// they receive it, rather that waiting until presigning completes.
    pub(crate) fn new_from_digest(
        digest: Keccak256,
        record: PresignRecord<C>,
        public_key_shares: Vec<KeySharePublic<C>>,
        threshold: usize,
        shift: Option<C::Scalar>,
    ) -> Self {
        Self {
            digest,
            presign_record: record,
            public_key_shares,
            threshold,
            shift,
        }
    }

    /// Retrieve the presign record.
    pub(crate) fn presign_record(&self) -> &PresignRecord<C> {
        &self.presign_record
    }

    /// Retrieve the shift value.
    fn shift_value(&self) -> C::Scalar {
        self.shift.unwrap_or(C::Scalar::zero())
    }

    /// Compute the digest. Note that this forces a clone of the [`Keccak256`]
    /// object.
    pub(crate) fn digest_hash(&self) -> GenericArray<u8, U32> {
        self.digest.clone().finalize()
    }

    /// Compute the public key.
    pub fn public_key(&self) -> Result<C::VerifyingKey> {
        // Add up all the key shares
        let public_key_point = self
            .public_key_shares
            .iter()
            .fold(C::IDENTITY, |sum, share| sum + *share.as_ref());

        C::VerifyingKey::from_point(public_key_point)
    }
}

/// Context for fiat-Shamir proofs generated in the non-interactive signing
/// protocol.
///
/// Note that this is only used in the case of identifiable abort, which is not
/// yet implemented. A correct execution of signing does not involve any ZK
/// proofs.
pub(crate) struct SignContext<C: CurveTrait> {
    shared_context: SharedContext<C>,
    message_digest: [u8; 32],
}

impl<C: CurveTrait> ProofContext for SignContext<C> {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok([
            self.shared_context.as_bytes()?,
            self.message_digest.to_vec(),
        ]
        .concat())
    }
}

impl<C: CurveTrait> SignContext<C> {
    /// Build a [`SignContext`] from a [`SignParticipant`].
    pub(crate) fn collect(p: &SignParticipant<C>) -> Self {
        Self {
            shared_context: SharedContext::collect(p),
            message_digest: p.input.digest_hash().into(),
        }
    }
}

mod storage {

    use crate::{
        curve::CurveTrait, local_storage::TypeTag,
        sign::non_interactive_sign::share::SignatureShare,
    };
    pub(super) struct Share<C: CurveTrait> {
        _c: std::marker::PhantomData<C>,
    }
    impl<C: CurveTrait> TypeTag for Share<C> {
        type Value = SignatureShare<C>;
    }

    pub(super) struct XProj<C: CurveTrait> {
        _c: std::marker::PhantomData<C>,
    }
    impl<C: CurveTrait> TypeTag for XProj<C> {
        type Value = C::Scalar;
    }
}

impl<C: CurveTrait> ProtocolParticipant for SignParticipant<C> {
    type Input = Input<C>;
    type Output = C::ECDSASignature;

    fn ready_type() -> MessageType {
        MessageType::Sign(SignMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Sign
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

        // The input must contain exactly one public key per participant ID.
        let public_key_pids = input
            .public_key_shares
            .iter()
            .map(|share| share.participant())
            .collect::<HashSet<_>>();
        let pids = std::iter::once(id)
            .chain(other_participant_ids)
            .collect::<HashSet<_>>();
        if public_key_pids != pids || config.count() != input.public_key_shares.len() {
            Err(CallerError::BadInput)?
        }
        if config.count() < input.threshold {
            Err(CallerError::BadInput)?
        }

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

        if !self.status().is_ready() && message.message_type() != Self::ready_type() {
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

    fn status(&self) -> &Status {
        &self.status
    }

    fn sid(&self) -> Identifier {
        self.sid
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for SignParticipant<C> {
    type Context = SignContext<C>;

    fn retrieve_context(&self) -> Self::Context {
        SignContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.storage
    }

    fn status_mut(&mut self) -> &mut Status {
        &mut self.status
    }
}

impl<C: CurveTrait> SignParticipant<C> {
    /// Compute the public key with the shift value applied.
    pub fn shifted_public_key(
        &self,
        public_key_shares: Vec<KeySharePublic<C>>,
        shift: C::Scalar,
    ) -> Result<C::VerifyingKey> {
        // Add up all the key shares
        let public_key_point = public_key_shares
            .iter()
            .fold(C::IDENTITY, |sum, share| sum + *share.as_ref());

        let shifted_point = C::GENERATOR.mul(&shift);
        let shifted_public_key_point = public_key_point + shifted_point;

        C::VerifyingKey::from_point(shifted_public_key_point)
    }

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
            .contains_for_all_ids::<storage::Share<C>>(&self.all_participants())
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
        let digest_bytes = self.input.digest_hash();
        // Compute the digest as a C::Scalar
        let digest = C::Scalar::from_bytes(&digest_bytes)?.unwrap();

        // Compute the x-projection of `R` from the `PresignRecord`
        let x_projection = record.x_projection()?;

        // Compute the share
        let share = SignatureShare::<C>::new(
            record
                .mask_share()
                .mul(&digest)
                .add(&x_projection.mul(record.masked_key_share()))
                .add(&x_projection.mul(&record.mask_share().mul(&self.input.shift_value()))),
        );

        // Erase the presign record
        self.input.presign_record.zeroize();

        // Save pieces for our own use later
        self.storage
            .store::<storage::Share<C>>(self.id(), share.clone());
        self.storage
            .store::<storage::XProj<C>>(self.id(), x_projection);

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
        if !self.status().is_ready() {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        self.check_for_duplicate_msg::<storage::Share<C>>(message.from())?;

        // Save this signature share
        let share = SignatureShare::try_from(message)?;
        self.storage
            .store_once::<storage::Share<C>>(message.from(), share)?;

        // If we haven't received shares from all parties, stop here
        if !self
            .storage
            .contains_for_all_ids::<storage::Share<C>>(&self.all_participants())
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

        // Retrieve everyone's id and share
        let shares = self
            .all_participants()
            .into_iter()
            .map(|pid| self.storage.remove::<storage::Share<C>>(pid))
            .collect::<Result<Vec<_>>>()?;

        let x_projection = self.storage.remove::<storage::XProj<C>>(self.id())?;

        // Sum up the signature shares and convert to BIP-0062 format (negating if the
        // sum is > group order /2)
        let mut sum = shares
            .into_iter()
            .fold(C::Scalar::zero(), |a, b| a.add(&b.0));

        if sum.is_high() {
            sum = sum.negate();
        }

        let signature = C::ECDSASignature::from_scalars(
            &C::scalar_to_bn(&x_projection),
            &C::scalar_to_bn(&sum),
        )?;

        self.shifted_public_key(
            self.input.public_key_shares.clone(),
            self.input.shift_value(),
        )?
        .verify_signature(self.input.digest.clone(), signature)
        .map_err(|e| {
            error!("Failed to verify signature {:?}", e);
            InternalError::ProtocolError(None)
        })?;

        // Output full signature
        self.status = Status::TerminatedSuccessfully;
        Ok(ProcessOutcome::Terminated(signature))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        curve::{SignatureTrait, TestCurve, VerifyingKeyTrait},
        ParticipantIdentifier,
    };
    use std::{collections::HashMap, ops::Deref};

    use k256::{
        ecdsa::{signature::DigestVerifier, RecoveryId},
        elliptic_curve::ops::Reduce,
        U256,
    };
    use rand::{CryptoRng, Rng, RngCore};
    use sha3::{Digest, Keccak256};
    use tracing::debug;

    use crate::{
        curve::{CurveTrait, ScalarTrait},
        errors::Result,
        keygen,
        messages::{Message, MessageType},
        participant::{ProcessOutcome, Status},
        presign, sign,
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ProtocolParticipant,
    };
    type PresignRecord = presign::PresignRecord<TestCurve>;

    type SignParticipant = super::SignParticipant<TestCurve>;

    /// Pick a random incoming message and have the correct participant process
    /// it.
    fn process_messages<'a, R: RngCore + CryptoRng>(
        quorum: &'a mut [SignParticipant],
        inbox: &mut Vec<Message>,
        rng: &mut R,
    ) -> Option<(
        &'a SignParticipant,
        ProcessOutcome<<TestCurve as CurveTrait>::ECDSASignature>,
    )> {
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
        keygen_outputs: &[keygen::Output<TestCurve>],
    ) -> <TestCurve as CurveTrait>::ECDSASignature {
        let k = records
            .iter()
            .map(|record| record.mask_share())
            .fold(<TestCurve as CurveTrait>::Scalar::zero(), |a, b| a + b);

        let secret_key = keygen_outputs
            .iter()
            .map(|output| TestCurve::bn_to_scalar(output.private_key_share().as_ref()).unwrap())
            .fold(<TestCurve as CurveTrait>::Scalar::zero(), |a, b| a + b);

        let r = records[0].x_projection().unwrap();

        let m = <<TestCurve as CurveTrait>::Scalar as Reduce<U256>>::reduce_bytes(
            &Keccak256::digest(message),
        );

        let mut s: <TestCurve as CurveTrait>::Scalar = k * (m + r * secret_key);

        if s.is_high() {
            s = s.negate();
        }

        let signature = <TestCurve as CurveTrait>::ECDSASignature::from_scalars(
            &<TestCurve as CurveTrait>::scalar_to_bn(&r),
            &<TestCurve as CurveTrait>::scalar_to_bn(&s),
        )
        .unwrap();

        // These checks fail when the overall thing fails
        let public_key: <TestCurve as CurveTrait>::VerifyingKey =
            keygen_outputs[0].public_key().unwrap();

        assert!(public_key
            .verify_signature(Keccak256::new_with_prefix(message), signature)
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
        let digest = Keccak256::new_with_prefix(message);

        // Save some things for later -- a signature constructucted from the records and
        // the public key
        let non_distributed_sig =
            compute_non_distributed_ecdsa(message, &presign_records, &keygen_outputs);
        let public_key = &keygen_outputs[0].public_key().unwrap();

        // Form signing inputs and participants
        let inputs = std::iter::zip(keygen_outputs, presign_records).map(|(keygen, record)| {
            sign::Input::new(
                message,
                record,
                keygen.public_key_shares().to_vec(),
                quorum_size,
                None,
            )
        });
        let mut quorum = std::iter::zip(configs, inputs)
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
        assert_eq!(distributed_sig, &non_distributed_sig);

        // Verify that we have a valid signature under the public key for the `message`
        assert!(public_key
            .verify_digest(digest.clone(), distributed_sig.deref())
            .is_ok());

        // Check we are able to create a recoverable signature.
        let recid =
            RecoveryId::trial_recovery_from_digest(public_key, digest.clone(), distributed_sig)
                .expect("Failed to recover signature");
        let recovered_pk = <TestCurve as CurveTrait>::VerifyingKey::recover_from_digest(
            digest,
            distributed_sig,
            RecoveryId::from_byte(recid.into()).expect("Invalid recovery ID"),
        )
        .unwrap();
        assert_eq!(
            recovered_pk, *public_key,
            "Recovered public key does not match original one."
        );

        Ok(())
    }

    // test threshold signature with less than t participants
    #[test]
    fn signing_fails_with_less_than_threshold() -> Result<()> {
        // create SignParticipant
        let threshold = 3;
        let rng = &mut init_testing();
        let sid = Identifier::random(rng);

        // create participant_ids
        let id = ParticipantIdentifier::random(rng);
        // not enough other participants
        let other_participant_ids = (0..threshold - 2)
            .map(|_| ParticipantIdentifier::random(rng))
            .collect::<Vec<_>>();
        let participant_ids = std::iter::once(id)
            .chain(other_participant_ids.clone())
            .collect::<Vec<_>>();

        // create input
        let message = b"the quick brown fox jumped over the lazy dog";
        let keygen_output = keygen::Output::simulate(&participant_ids, rng);
        let presign_record = PresignRecord::simulate();
        let input = sign::Input::new(
            message,
            presign_record,
            keygen_output.public_key_shares().to_vec(),
            threshold,
            None,
        );

        let participant = SignParticipant::new(sid, id, other_participant_ids, input);
        assert!(participant.is_err());
        Ok(())
    }
}
