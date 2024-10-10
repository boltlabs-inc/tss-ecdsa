//! Types and functions related to the key refresh sub-protocol Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::collections::HashMap;

use super::{
    commit::{TshareCommit, TshareDecommit},
    share::{CoeffPrivate, CoeffPublic, EvalEncrypted, EvalPrivate},
};
use crate::{
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{CallerError, InternalError, Result},
    keygen::{KeySharePrivate, KeySharePublic, KeygenParticipant},
    local_storage::LocalStorage,
    messages::{Message, MessageType, TshareMessageType},
    participant::{
        Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant, Status,
    },
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    run_only_once,
    tshare::share::EvalPublic,
    utils::{bn_to_scalar, scalar_to_bn, CurvePoint},
    zkp::pisch::{CommonInput, PiSchPrecommit, PiSchProof, ProverSecret},
    Identifier, ParticipantConfig,
};

use k256::{elliptic_curve::PrimeField, Scalar};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use tracing::{error, info, instrument, warn};

use super::{input::Input, output::Output};

mod storage {
    use super::*;
    use crate::{local_storage::TypeTag, tshare::share::EvalPublic};

    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = TshareCommit;
    }
    pub(super) struct Decommit;
    impl TypeTag for Decommit {
        type Value = TshareDecommit;
    }
    pub(super) struct SchnorrPrecom;
    impl TypeTag for SchnorrPrecom {
        type Value = PiSchPrecommit;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct PrivateCoeffs;
    impl TypeTag for PrivateCoeffs {
        type Value = Vec<super::CoeffPrivate>;
    }
    pub(super) struct PublicCoeffs;
    impl TypeTag for PublicCoeffs {
        type Value = Vec<super::CoeffPublic>;
    }
    pub(super) struct ValidPublicShare;
    impl TypeTag for ValidPublicShare {
        type Value = EvalPublic;
    }
    pub(super) struct ValidPrivateEval;
    impl TypeTag for ValidPrivateEval {
        type Value = super::EvalPrivate;
    }
}

/**
This is a protocol that converts additive shares to Shamir shares.

Input:
- The threshold `t` of parties needed to reconstruct the shared secret.
- The auxiliary information for encryption.
- Optionally, an existing n-out-of-n share to be converted to t-out-of-n.

Rounds 1:
- Each participant generates a random polynomial of degree `threshold - 1`.
    - Alternatively, set an existing additive share as the constant term.
- Each participant commits to their polynomial.

Rounds 2:
- Each participant decommits the public form of their polynomial.

Rounds 3:
- Each participant prove knowledge of their private shares.

Output:
- The public commitment to the shared polynomial. It is represented in coefficients form in the exponent (EC points).
The constant term corresponds to the shared value. This can be used to evaluate the commitment to the share of any participant.
- The private evaluation of the shared polynomial for our participant. `t` of those can reconstruct the secret.

*/
#[derive(Debug)]
pub struct TshareParticipant {
    /// The current session identifier
    sid: Identifier,
    /// The current protocol input.
    input: Input,
    /// A unique identifier for this participant.
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    /// Broadcast subprotocol handler
    broadcast_participant: BroadcastParticipant,
    /// Status of the protocol execution.
    status: Status,
}

impl ProtocolParticipant for TshareParticipant {
    type Input = Input;
    type Output = Output;

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self> {
        input.check_participant_config(&ParticipantConfig::new(id, &other_participant_ids)?)?;

        Ok(Self {
            sid,
            input,
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: Default::default(),
            broadcast_participant: BroadcastParticipant::new(sid, id, other_participant_ids, ())?,
            status: Status::NotReady,
        })
    }

    fn ready_type() -> MessageType {
        MessageType::Tshare(TshareMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Tshare
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        &self.other_participant_ids
    }

    fn sid(&self) -> Identifier {
        self.sid
    }

    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "TSHARE: Player {}: received {:?} from {}",
            self.id(),
            message.message_type(),
            message.from()
        );

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
        }

        if !self.status().is_ready() && message.message_type() != Self::ready_type() {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        match message.message_type() {
            MessageType::Tshare(TshareMessageType::Ready) => self.handle_ready_msg(rng, message),
            MessageType::Tshare(TshareMessageType::R1CommitHash) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_msg, rng)
            }
            MessageType::Tshare(TshareMessageType::R2Decommit) => {
                self.handle_round_two_msg(message)
            }
            MessageType::Tshare(TshareMessageType::R2PrivateShare) => {
                self.handle_round_two_msg_private(message)
            }
            MessageType::Tshare(TshareMessageType::R3Proof) => self.handle_round_three_msg(message),
            message_type => {
                error!(
                    "Incorrect MessageType given to TshareParticipant. Got: {:?}",
                    message_type
                );
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    fn status(&self) -> &Status {
        &self.status
    }
}

impl InnerProtocolParticipant for TshareParticipant {
    type Context = SharedContext;

    fn retrieve_context(&self) -> <Self as InnerProtocolParticipant>::Context {
        SharedContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.local_storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.local_storage
    }

    fn status_mut(&mut self) -> &mut Status {
        &mut self.status
    }
}

impl Broadcast for TshareParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl TshareParticipant {
    /// Handle "Ready" messages from the protocol participants.
    ///
    /// Once "Ready" messages have been received from all participants, this
    /// method will trigger this participant to generate its round one message.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling ready tshare message.");

        let ready_outcome = self.process_ready_message(rng, message)?;
        let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, message.id()))?;
        // extend the output with r1 messages (if they hadn't already been generated)
        Ok(ready_outcome.with_messages(round_one_messages))
    }

    /// Generate the protocol's round one message.
    ///
    /// The outcome is a broadcast message containing a commitment to:
    /// - shares [`CoeffPublic`] X_ij for all other participants,
    /// - a "pre-commitment" A to a Schnorr proof.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one tshare messages.");

        // Generate shares for all participants.
        let (coeff_privates, coeff_publics) = {
            let mut privates = vec![];
            let mut publics = vec![];

            for _ in 0..self.input.threshold() {
                let (private, public) = CoeffPublic::new_pair(rng)?;
                privates.push(private);
                publics.push(public);
            }

            if let Some(private) = self.input.share() {
                privates[0] = private.clone();
                publics[0] = private.to_public();
            }

            (privates, publics)
        };

        // Generate proof precommitments.
        let sch_precom = PiSchProof::precommit(rng)?;

        // Store the beginning of our proofs so we can continue the proofs later.
        self.local_storage
            .store::<storage::SchnorrPrecom>(self.id(), sch_precom.clone());

        let decom = TshareDecommit::new(
            rng,
            &sid,
            &self.id(),
            &coeff_publics,
            *sch_precom.precommitment(),
        );

        // Store the private coeffs from us to others so we can share them later.
        self.local_storage
            .store::<storage::PrivateCoeffs>(self.id(), coeff_privates);

        // Store the public coeffs from us to others so we can share them later.
        self.local_storage
            .store::<storage::PublicCoeffs>(self.id(), coeff_publics);

        let com = decom.commit()?;
        let com_bytes = serialize!(&com)?;
        self.local_storage.store::<storage::Commit>(self.id(), com);

        // Store our committed values so we can open the commitment later.
        self.local_storage
            .store::<storage::Decommit>(self.id(), decom);

        let messages = self.broadcast(
            rng,
            MessageType::Tshare(TshareMessageType::R1CommitHash),
            com_bytes,
            sid,
            BroadcastTag::TshareR1CommitHash,
        )?;
        Ok(messages)
    }

    /// Handle round one messages from the protocol participants.
    ///
    /// In round one, each participant broadcasts its commitment to its public
    /// key share and a "precommitment" to a Schnorr proof. Once all such
    /// commitments have been received, this participant will send an opening of
    /// its own commitment to all other parties.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: BroadcastOutput,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        let message = broadcast_message.into_message(BroadcastTag::TshareR1CommitHash)?;

        self.check_for_duplicate_msg::<storage::Commit>(message.from())?;
        info!("Handling round one tshare message.");

        let tshare_commit = TshareCommit::from_message(&message)?;
        self.local_storage
            .store_once::<storage::Commit>(message.from(), tshare_commit)?;

        // Check if we've received all the commits, which signals an end to
        // round one.
        //
        // Note: This does _not_ check `self.all_participants` on purpose. There
        // could be a setting where we've received all the round one messages
        // from all other participants, yet haven't ourselves generated our
        // round one message. If we switched to `self.all_participants` here
        // then the result would be `false`, causing the execution to hang.
        //
        // The "right" solution would be to only process the message once the
        // "Ready" round is complete, and stashing messages if it is not yet
        // complete (a la how we do it in `handle_round_two_msg`).
        // Unfortunately, this does not work given the current API because we
        // are dealing with a [`BroadcastOutput`] type instead of a [`Message`]
        // type.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(self.other_ids());

        if r1_done {
            // Finish round 1 by generating messages for round 2
            let round_one_messages = run_only_once!(self.gen_round_two_msgs(rng, message.id()))?;

            // Process any round 2 messages we may have received early
            let round_two_outcomes = self
                .fetch_messages(MessageType::Tshare(TshareMessageType::R2Decommit))?
                .iter()
                .map(|msg| self.handle_round_two_msg(msg))
                .collect::<Result<Vec<_>>>()?;

            ProcessOutcome::collect_with_messages(round_two_outcomes, round_one_messages)
        } else {
            // Otherwise, wait for more round 1 messages
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate the protocol's round two messages.
    ///
    /// The outcome is an opening to the commitment generated in round one.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two tshare messages.");

        let mut messages = vec![];
        // Check that we've generated our share before trying to retrieve it.
        //
        // Because we are not checking `self.all_participants` in
        // `handle_round_one_msg`, we may reach this point and not actually have
        // generated round one messages for ourselves (in particular,
        // `CoeffPublic` and `Decommit`). This check forces that behavior.
        // Without it we'll get a `InternalInvariantFailed` error when trying to
        // retrieve `Decommit` below.
        if !self.local_storage.contains::<storage::Decommit>(self.id()) {
            let more_messages = run_only_once!(self.gen_round_one_msgs(rng, sid))?;
            messages.extend_from_slice(&more_messages);
        }

        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(self.id())?;
        let more_messages = self.message_for_other_participants(
            MessageType::Tshare(TshareMessageType::R2Decommit),
            decom,
        )?;
        messages.extend_from_slice(&more_messages);

        let private_coeffs = self
            .local_storage
            .retrieve::<storage::PrivateCoeffs>(self.id())?;

        // Encrypt the private shares to each participant.
        let encrypted_shares = self
            .other_ids()
            .iter()
            .map(|other_participant_id| {
                let private_share = Self::eval_private_share(private_coeffs, *other_participant_id);

                let auxinfo = self.input.find_auxinfo_public(*other_participant_id)?;
                EvalEncrypted::encrypt(&private_share, auxinfo.pk(), rng)
            })
            .collect::<Result<Vec<_>>>()?;

        // Send their private shares to each individual participant.
        messages.extend(
            self.other_ids()
                .iter()
                .zip(encrypted_shares.iter())
                .map(|(other_participant_id, encrypted_share)| {
                    Message::new(
                        MessageType::Tshare(TshareMessageType::R2PrivateShare),
                        self.sid(),
                        self.id(),
                        *other_participant_id,
                        encrypted_share,
                    )
                })
                .collect::<Result<Vec<Message>>>()?,
        );

        Ok(messages)
    }

    /// Handle the protocol's round two messages.
    ///
    /// Here we check that the decommitments from each participant are valid.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::Decommit>(message.from())?;
        info!("Handling round two tshare message.");

        // We must receive all commitments in round 1 before we start processing
        // decommits in round 2.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(&self.all_participants());
        if !r1_done {
            // Store any early round 2 messages
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        // Check that the decommitment contained in the message is valid against
        // the previously received commitment and protocol rules.
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(message.from())?;
        let decom = TshareDecommit::from_message(message, com)?;
        self.local_storage
            .store_once::<storage::Decommit>(message.from(), decom)?;

        // Check if we've received all the decommits
        let r2_done = self
            .local_storage
            .contains_for_all_ids::<storage::Decommit>(&self.all_participants());

        if r2_done {
            // Generate messages for round 3...
            let round_three_messages = run_only_once!(self.gen_round_three_msgs())?;

            let mut round_outcomes = self
                .fetch_messages(MessageType::Tshare(TshareMessageType::R2PrivateShare))?
                .iter()
                .map(|msg| self.handle_round_two_msg_private(msg))
                .collect::<Result<Vec<_>>>()?;

            // ...and handle any messages that other participants have sent for round 3.
            let round_three_outcomes = self
                .fetch_messages(MessageType::Tshare(TshareMessageType::R3Proof))?
                .iter()
                .map(|msg| self.handle_round_three_msg(msg))
                .collect::<Result<Vec<_>>>()?;

            //round_three_outcomes.extend(outcomes_private);
            round_outcomes.extend(round_three_outcomes);

            ProcessOutcome::collect_with_messages(round_outcomes, round_three_messages)
        } else {
            // Otherwise, wait for more round 2 messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate the protocol's round three messages.
    ///
    /// At this point, we have validated each participant's commitment, and can
    /// now proceed to constructing a Schnorr proof that this participant knows
    /// the private value corresponding to its public key share.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs(&mut self) -> Result<Vec<Message>> {
        info!("Generating round three tshare messages.");

        // Construct `global rid` out of each participant's `rid`s.
        let my_rid = self
            .local_storage
            .retrieve::<storage::Decommit>(self.id())?
            .rid;
        let rids: Vec<[u8; 32]> = self
            .other_ids()
            .iter()
            .map(|&other_participant_id| {
                let decom = self
                    .local_storage
                    .retrieve::<storage::Decommit>(other_participant_id)?;
                Ok(decom.rid)
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let mut global_rid = my_rid;
        // xor all the rids together.
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.local_storage
            .store::<storage::GlobalRid>(self.id(), global_rid);

        let transcript = schnorr_proof_transcript(self.sid(), &global_rid, self.id())?;

        let private_coeffs = self
            .local_storage
            .retrieve::<storage::PrivateCoeffs>(self.id())?;

        let my_private_share = Self::eval_private_share(private_coeffs, self.id());
        let my_contant_term = Self::eval_private_share_at_zero(private_coeffs);
        if let Some(private) = self.input.share() {
            assert_eq!(my_contant_term, private.x);
        }
        let public_share = EvalPublic::new(my_private_share.public_point());

        // Generate proofs for each share.
        let precom = self
            .local_storage
            .retrieve::<storage::SchnorrPrecom>(self.id())?;

        let pk = &public_share;
        let input = CommonInput::new(pk);
        let sk = &my_private_share.x;

        let proof = PiSchProof::prove_from_precommit(
            &self.retrieve_context(),
            precom,
            &input,
            &ProverSecret::new(&scalar_to_bn(sk)),
            &transcript,
        )?;

        self.local_storage
            .store::<storage::ValidPrivateEval>(self.id(), my_private_share.clone());
        self.local_storage
            .store::<storage::ValidPublicShare>(self.id(), public_share.clone());

        // Send all proofs to everybody.
        let messages = self.message_for_other_participants(
            MessageType::Tshare(TshareMessageType::R3Proof),
            proof,
        )?;

        Ok(messages)
    }

    /// Assign a non-null x coordinate to each participant.
    fn participant_coordinate(pid: ParticipantIdentifier) -> Scalar {
        Scalar::from_u128(pid.as_u128()) + Scalar::ONE
    }

    /// Evaluate the private share
    pub fn eval_private_share(
        coeff_privates: &[CoeffPrivate],
        recipient_id: ParticipantIdentifier,
    ) -> EvalPrivate {
        let x = Self::participant_coordinate(recipient_id);
        assert!(x > Scalar::ZERO);
        let mut sum = Scalar::ZERO;
        for coeff in coeff_privates.iter().rev() {
            sum *= &x;
            sum += &coeff.x;
        }
        EvalPrivate { x: sum }
    }

    /// Evaluate the private share at the point 0.
    fn eval_private_share_at_zero(coeff_privates: &[CoeffPrivate]) -> Scalar {
        coeff_privates[0].x
    }

    /// Feldman VSS evaluation of the public share.
    /// This algorithm is slow. Consider using MSMs.
    pub(crate) fn eval_public_share(
        coeff_publics: &[CoeffPublic],
        recipient_id: ParticipantIdentifier,
    ) -> Result<CurvePoint> {
        let x = Self::participant_coordinate(recipient_id);
        let mut sum = CurvePoint::IDENTITY;
        for coeff in coeff_publics.iter().rev() {
            sum = sum.multiply_by_scalar(&x);
            sum = sum + *coeff.as_ref();
        }
        Ok(sum)
    }

    /// Convert the tshares to t-out-of-t shares.
    /// This is done by multiplying the shares by the Lagrange coefficients.
    /// Since the constant term is the secret, we need to multiply by the
    /// Lagrange coefficient at zero. This is done by the function
    /// `lagrange_coefficient_at_zero`.
    /// Also convert the public tshares in the same way as the private shares.
    /// Finally a vector of all public keys is returned.
    #[allow(clippy::type_complexity)]
    pub fn convert_to_t_out_of_t_shares(
        tshares: HashMap<ParticipantIdentifier, Output>,
        all_participants: Vec<ParticipantIdentifier>,
        chain_code: [u8; 32],
        rid: [u8; 32],
    ) -> Result<(
        HashMap<ParticipantIdentifier, <KeygenParticipant as ProtocolParticipant>::Output>,
        Vec<KeySharePublic>,
    )> {
        let mut new_private_shares = HashMap::new();
        let mut public_keys = vec![];

        // Compute the new private shares and public keys.
        for pid in tshares.keys() {
            if all_participants.contains(pid) {
                let output = tshares.get(pid).unwrap();
                let private_key = output.private_key_share();
                let private_share = KeySharePrivate::from_bigint(&scalar_to_bn(private_key));
                let public_share = CurvePoint::GENERATOR.multiply_by_scalar(private_key);
                let lagrange = Self::lagrange_coefficient_at_zero(pid, &all_participants);
                let new_private_share: BigNumber =
                    private_share.clone().as_ref() * BigNumber::from_slice(lagrange.to_bytes());
                let new_public_share = public_share.as_ref().multiply_by_scalar(&lagrange);
                assert!(new_private_shares
                    .insert(*pid, KeySharePrivate::from_bigint(&new_private_share))
                    .is_none());
                public_keys.push(KeySharePublic::new(*pid, new_public_share));
            }
        }

        // Compute the new outputs
        let mut keygen_outputs: HashMap<
            ParticipantIdentifier,
            <KeygenParticipant as ProtocolParticipant>::Output,
        > = HashMap::new();
        for (pid, private_key_share) in new_private_shares {
            let output = crate::keygen::Output::from_parts(
                public_keys.clone(),
                private_key_share,
                chain_code,
                rid,
            )?;
            assert!(keygen_outputs.insert(pid, output).is_none());
        }
        Ok((keygen_outputs, public_keys))
    }

    /// Reconstruct the secret from the shares.
    /// Use lagrange_coefficients_at_zero to get the constant term.
    pub fn reconstruct_secret(
        shares: HashMap<ParticipantIdentifier, KeySharePrivate>,
        all: Vec<ParticipantIdentifier>,
    ) -> Result<Scalar> {
        let mut secret = Scalar::ZERO;
        // compute the coordinates
        for (id, share) in shares.iter() {
            let lagrange = Self::lagrange_coefficient_at_zero(id, &all);
            let t_out_of_t_share = lagrange * bn_to_scalar(share.clone().as_ref()).unwrap();
            secret += t_out_of_t_share;
        }
        Ok(secret)
    }

    /// Compute the Lagrange coefficient evaluated at zero.
    /// This is used to reconstruct the secret from the shares.
    pub fn lagrange_coefficient_at_zero(
        my_point: &ParticipantIdentifier,
        other_points: &Vec<ParticipantIdentifier>,
    ) -> Scalar {
        let mut result = Scalar::ONE;
        for point in other_points {
            if point != my_point {
                let point_coordinate = &Self::participant_coordinate(*point);
                let my_point_coordinate = &Self::participant_coordinate(*my_point);
                let numerator = Scalar::ZERO - point_coordinate;
                let denominator = my_point_coordinate - point_coordinate;
                let inv = denominator.invert().unwrap();
                result *= numerator * inv;
            }
        }
        result
    }

    /// Handle the protocol's round two private messages.
    ///
    /// Here we validate and store a private share from someone to us.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg_private(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::ValidPrivateEval>(message.from())?;

        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three tshare private message.");
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        info!("Handling round three tshare private message.");

        message.check_type(MessageType::Tshare(TshareMessageType::R2PrivateShare))?;
        let encrypted_share: EvalEncrypted = deserialize!(&message.unverified_bytes)?;

        // Get my private key from the AuxInfo protocol.
        let my_dk = self.input.private_auxinfo().decryption_key();

        // Decrypt the private share.
        let private_share = encrypted_share.decrypt(my_dk)?;

        // Feldman validation
        // Check that this private share matches our public share in TshareDecommit
        // from this participant.
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;
        let coeff_publics = decom.coeff_publics.clone();
        let expected_public = Self::eval_public_share(coeff_publics.as_slice(), self.id())?;
        let implied_public = private_share.public_point();
        if implied_public != expected_public {
            error!("the private share does not match the public share");
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        self.local_storage
            .store::<storage::ValidPrivateEval>(message.from(), private_share);

        self.local_storage
            .store::<storage::PublicCoeffs>(message.from(), coeff_publics);

        self.maybe_finish()
    }

    /// Handle round three messages only after our own `gen_round_three_msgs`.
    fn can_handle_round_three_msg(&self) -> bool {
        self.local_storage.contains::<storage::GlobalRid>(self.id())
    }

    /// Handle the protocol's round three public messages.
    ///
    /// Here we validate the Schnorr proofs from each participant.
    #[cfg_attr(feature = "flame_it", flame("tshare"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        self.check_for_duplicate_msg::<storage::ValidPublicShare>(message.from())?;

        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three tshare broadcast message.");
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        info!("Handling round three tshare broadcast message.");

        let global_rid = *self
            .local_storage
            .retrieve::<storage::GlobalRid>(self.id())?;

        let proof = PiSchProof::from_message(message)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;
        // calculate public share from the public coefficients
        let public_share = Self::eval_public_share(&decom.coeff_publics, message.from())?;
        let public_share = EvalPublic::new(public_share);

        let mut transcript = schnorr_proof_transcript(self.sid(), &global_rid, message.from())?;
        proof.verify_with_precommit(
            CommonInput::new(&public_share),
            &self.retrieve_context(),
            &mut transcript,
            &decom.precom,
        )?;

        // Only if the proof verifies do we store the participant's shares.
        self.local_storage
            .store_once::<storage::ValidPublicShare>(message.from(), public_share.clone())?;

        self.maybe_finish()
    }

    fn maybe_finish(&mut self) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        // Have we validated and stored the public shares from everybody to everybody?
        let got_all_public_shares = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPublicShare>(&self.all_participants());

        // Have we got the private shares from everybody to us?
        let got_all_private_shares = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPrivateEval>(&self.all_participants());

        // If so, we completed the protocol! Return the outputs.
        if got_all_public_shares && got_all_private_shares {
            // Compute the public polynomial.
            let coeffs_from_all = self
                .all_participants()
                .iter()
                .map(|pid| self.local_storage.remove::<storage::PublicCoeffs>(*pid))
                .collect::<Result<Vec<_>>>()?;
            let all_public_coeffs = Self::aggregate_public_coeffs(&coeffs_from_all);

            // Compute the one's own private evaluation.
            let from_all_to_me_private = self
                .all_participants()
                .iter()
                .map(|pid| self.local_storage.remove::<storage::ValidPrivateEval>(*pid))
                .collect::<Result<Vec<_>>>()?;
            let my_private_share = Self::aggregate_private_shares(&from_all_to_me_private);

            // Double-check that the aggregated private share matches the aggregated public
            // coeffs.
            let my_public_share = my_private_share.public_point();
            let mut all_public_keys = vec![];
            for pid in self.other_participant_ids.iter() {
                let public_share = Self::eval_public_share(&all_public_coeffs, *pid)?;
                let public_share = KeySharePublic::new(*pid, public_share);
                all_public_keys.push(public_share);
            }
            all_public_keys.push(KeySharePublic::new(self.id(), my_public_share));

            let output = Output::from_parts(
                all_public_coeffs.clone(),
                all_public_keys,
                my_private_share.x,
            )?;

            self.status = Status::TerminatedSuccessfully;
            Ok(ProcessOutcome::Terminated(output))
        } else {
            // Otherwise, we'll have to wait for more round three messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    fn aggregate_private_shares(private_shares: &[EvalPrivate]) -> EvalPrivate {
        EvalPrivate::sum(private_shares)
    }

    /// Return coeffs.sum(axis=0)
    fn aggregate_public_coeffs(coeffs_from_all: &[Vec<CoeffPublic>]) -> Vec<CoeffPublic> {
        let n_coeffs = coeffs_from_all[0].len();
        (0..n_coeffs)
            .map(|i| {
                let sum = coeffs_from_all
                    .iter()
                    .fold(CurvePoint::IDENTITY, |sum, coeffs| {
                        sum + *coeffs[i].as_ref()
                    });
                CoeffPublic::new(sum)
            })
            .collect()
    }
}

/// Generate a [`Transcript`] for [`PiSchProof`].
fn schnorr_proof_transcript(
    sid: Identifier,
    global_rid: &[u8; 32],
    sender_id: ParticipantIdentifier,
) -> Result<Transcript> {
    let mut transcript = Transcript::new(b"tshare schnorr");
    transcript.append_message(b"sid", &serialize!(&sid)?);
    transcript.append_message(b"rid", &serialize!(global_rid)?);
    transcript.append_message(b"sender_id", &serialize!(&sender_id)?);
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use super::{super::input::Input, *};
    use crate::{auxinfo, utils::testing::init_testing_with_seed, Identifier, ParticipantConfig};
    use k256::elliptic_curve::{Field, PrimeField};
    use rand::{thread_rng, CryptoRng, Rng, RngCore};
    use std::{collections::HashMap, iter::zip};
    use tracing::debug;

    impl TshareParticipant {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            quorum_size: usize,
            share: Option<CoeffPrivate>,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            // Prepare prereqs for making TshareParticipant's. Assume all the
            // simulations are stable (e.g. keep config order)
            let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
            let auxinfo_outputs = auxinfo::Output::simulate_set(&configs, rng);

            // Make the participants
            zip(configs, auxinfo_outputs)
                .map(|(config, auxinfo_output)| {
                    let input = Input::new(auxinfo_output, share.clone(), 2)?;
                    Self::new(sid, config.id(), config.other_ids().to_vec(), input)
                })
                .collect::<Result<Vec<_>>>()
        }

        pub fn initialize_tshare_message(&self, tshare_identifier: Identifier) -> Result<Message> {
            let empty: [u8; 0] = [];
            Message::new(
                MessageType::Tshare(TshareMessageType::Ready),
                tshare_identifier,
                self.id(),
                self.id(),
                &empty,
            )
        }
    }

    /// Delivers all messages into their respective participant's inboxes.
    fn deliver_all(
        messages: &[Message],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    ) {
        for message in messages {
            inboxes
                .get_mut(&message.to())
                .unwrap()
                .push(message.clone());
        }
    }

    fn is_tshare_done(quorum: &[TshareParticipant]) -> bool {
        for participant in quorum {
            if *participant.status() != Status::TerminatedSuccessfully {
                return false;
            }
        }
        true
    }

    #[allow(clippy::type_complexity)]
    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut [TshareParticipant],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
    ) -> Option<(usize, ProcessOutcome<Output>)> {
        // Pick a random participant to process
        let index = rng.gen_range(0..quorum.len());
        let participant = quorum.get_mut(index).unwrap();

        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        if inbox.is_empty() {
            // No messages to process for this participant, so pick another participant
            return None;
        }
        let message = inbox.remove(rng.gen_range(0..inbox.len()));
        debug!(
            "processing participant: {}, with message type: {:?} from {}",
            &participant.id(),
            &message.message_type(),
            &message.from(),
        );
        Some((index, participant.process_message(rng, &message).unwrap()))
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    fn tshare_always_produces_valid_outputs() -> Result<()> {
        for size in 2..4 {
            tshare_produces_valid_outputs(size)?;
        }
        Ok(())
    }

    fn tshare_produces_valid_outputs(quorum_size: usize) -> Result<()> {
        let mut rng = init_testing_with_seed(Default::default());
        let sid = Identifier::random(&mut rng);
        let test_share = Some(CoeffPrivate {
            x: Scalar::from_u128(42),
        });
        let mut quorum = TshareParticipant::new_quorum(sid, quorum_size, test_share, &mut rng)?;
        let mut inboxes = HashMap::new();
        for participant in &quorum {
            let _ = inboxes.insert(participant.id(), vec![]);
        }

        let mut outputs = std::iter::repeat_with(|| None)
            .take(quorum_size)
            .collect::<Vec<_>>();

        for participant in &quorum {
            let inbox = inboxes.get_mut(&participant.id()).unwrap();
            inbox.push(participant.initialize_tshare_message(sid)?);
        }

        while !is_tshare_done(&quorum) {
            let (index, outcome) = match process_messages(&mut quorum, &mut inboxes, &mut rng) {
                None => continue,
                Some(x) => x,
            };

            // Deliver messages and save outputs
            match outcome {
                ProcessOutcome::Incomplete => {}
                ProcessOutcome::Processed(messages) => deliver_all(&messages, &mut inboxes),
                ProcessOutcome::Terminated(output) => outputs[index] = Some(output),
                ProcessOutcome::TerminatedForThisParticipant(output, messages) => {
                    deliver_all(&messages, &mut inboxes);
                    outputs[index] = Some(output);
                }
            }
        }

        // Make sure every player got an output
        let outputs: Vec<_> = outputs.into_iter().flatten().collect();
        assert_eq!(outputs.len(), quorum_size);

        // Make sure everybody agrees on the public parts.
        assert!(outputs
            .windows(2)
            .all(|o| o[0].public_coeffs() == o[1].public_coeffs()));
        assert!(outputs.windows(2).all(|o| {
            let first_pks = o[0].public_key_shares();
            let second_pks = o[1].public_key_shares();
            // for each element in first_pks, there must be a corresponding element in
            // second_pks
            first_pks.iter().all(|x| second_pks.iter().any(|y| x == y))
        }));

        // Check returned outputs
        //
        // Every participant should have a public output from every other participant
        // and, for a given participant, they should be the same in every output
        for participant in quorum.iter_mut() {
            // Check that each participant fully completed its broadcast portion.
            if let Status::ParticipantCompletedBroadcast(participants) =
                participant.broadcast_participant().status()
            {
                assert_eq!(participants.len(), participant.other_ids().len());
            } else {
                panic!("Broadcast not completed!");
            }
        }

        // Check that each participant's own `CoeffPublic` corresponds to their
        // `CoeffPrivate`
        for (output, pid) in outputs
            .iter()
            .zip(quorum.iter().map(ProtocolParticipant::id))
        {
            let publics_coeffs = output
                .public_coeffs()
                .iter()
                .map(|coeff| CoeffPublic::new(*coeff.as_ref()))
                .collect::<Vec<_>>();
            let public_share = TshareParticipant::eval_public_share(&publics_coeffs, pid)?;

            let expected_public_share =
                CurvePoint::GENERATOR.multiply_by_scalar(output.private_key_share());
            // if the output already contains the public key, then we don't need to
            // recompute and check it here.
            assert_eq!(public_share, expected_public_share);

            // get the public key from output and validate against the expected public share
            let public_key = output
                .public_key_shares()
                .iter()
                .find(|x| x.participant() == pid)
                .unwrap();
            assert_eq!(public_key.as_ref(), &public_share);
        }

        // validate the final public key, which is given by the sum of the public keys
        // of all participants
        let mut sum_public_keys_first = CurvePoint::IDENTITY;
        for public_key in outputs.first().unwrap().public_key_shares() {
            sum_public_keys_first = sum_public_keys_first + *public_key.as_ref();
        }
        for output in outputs.iter().skip(1) {
            let mut sum_public_keys = CurvePoint::IDENTITY;
            for public_key in output.public_key_shares() {
                sum_public_keys = sum_public_keys + *public_key.as_ref();
            }
            assert_eq!(sum_public_keys, sum_public_keys_first);
        }

        Ok(())
    }

    fn generate_polynomial<R: Rng>(t: usize, rng: &mut R) -> Vec<Scalar> {
        let mut coefficients = Vec::with_capacity(t);
        for _ in 0..t {
            coefficients.push(Scalar::random(&mut *rng));
        }
        coefficients
    }

    pub fn evaluate_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
        coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |acc, coef| acc * x + coef)
    }

    fn evaluate_at_points(coefficients: &[Scalar], points: &[Scalar]) -> Vec<Scalar> {
        points
            .iter()
            .map(|x| evaluate_polynomial(coefficients, x))
            .collect()
    }

    #[test]
    fn test_evaluate_points_at_zero() {
        let mut rng = thread_rng();
        let t: u128 = 3;
        let n: u128 = 7;
        let coefficients = generate_polynomial(t as usize, &mut rng);

        // test that reconstruction works as long as we have enough points
        for n in t..n {
            let points: Vec<Scalar> = (1..=n).map(|i: u128| Scalar::from_u128(i + 1)).collect();
            let values = evaluate_at_points(&coefficients, &points);

            let zero = Scalar::ZERO;
            let zero_value = evaluate_polynomial(&coefficients, &zero);

            let points: Vec<ParticipantIdentifier> = (1..=n)
                .map(|i: u128| ParticipantIdentifier::from_u128(i))
                .collect();
            let zero_value_reconstructed = values
                .iter()
                .zip(&points)
                .map(|(value, point)| {
                    *value * TshareParticipant::lagrange_coefficient_at_zero(point, &points)
                })
                .fold(Scalar::ZERO, |acc, x| acc + x);

            assert_eq!(zero_value, zero_value_reconstructed);
        }
    }
}
