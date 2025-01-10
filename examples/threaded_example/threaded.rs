//! ## Example usage of [`tss_ecdsa`] crate.
//!
//! Each [`Participant`] is represented by a worker thread. A main coordinator
//! is used to initiate sub-protocols and route messages between workers.
//!
//! **Note**: A trusted Coordinator is not required to run threshold ECDSA
//! protocol. Networking models with less trust include authenticated
//! point-to-point channels between the workers or an untrusted relay node that
//! routes authenticated messages between the workers.

//!
//! This example uses
//! [`std::sync::mpsc`] channels to communicate [`Message`]s
//! amongst the workers and coordinator.
//!
//! # Warning: Trust Model
//! This example does not implement sender authentication, which is required for
//! a secure deployment.
//!
//! This means that the coordinator is trusted to route messages correctly.
//! The workers and coordinator are trusted to not forge messages from other
//! participants.
//!
//! Sender authentication is omitted from this code for brevity.
mod utils;

use clap::{command, Parser};
use itertools::Itertools;
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use std::{
    any::Any,
    collections::HashMap,
    sync::mpsc::{channel, Receiver, Sender},
    thread,
};

use tracing::{debug, info, instrument, span, trace, Level};
use tracing_subscriber::{self, EnvFilter};
use tss_ecdsa::{
    auxinfo::{self, AuxInfoParticipant},
    keygen::{self, KeygenParticipant, Output},
    messages::Message,
    presign::{self, PresignParticipant},
    sign::{self, SignParticipant},
    tshare::{self, TshareParticipant},
    Identifier, Participant, ParticipantConfig, ParticipantIdentifier, ProtocolParticipant,
};
use utils::{MessageFromWorker, SubProtocol};
use uuid::Uuid;

const THRESHOLD: usize = 2;

/// A shared session ID must be agreed up on by workers. We use a central
/// coordinator to assign this session ID to workers.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct SessionId(Identifier);
/// A key ID uniquely identify a key and all corresponding private and public
/// key material across sub-protocols.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct KeyId(Uuid);

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Number of participant worker threads to use.
    #[arg(short, long, default_value_t = 3)]
    number_of_workers: usize,
}

/// Generic Storage for outputs of specific sub-protocols. Indexed by a `KeyId`
struct StoredOutput<P: ProtocolParticipant> {
    stored_output: HashMap<KeyId, P::Output>,
}

impl<P: ProtocolParticipant> StoredOutput<P> {
    fn new() -> Self {
        StoredOutput {
            stored_output: Default::default(),
        }
    }

    fn store(&mut self, id: KeyId, store: P::Output) {
        self.stored_output.insert(id, store);
    }

    fn retrieve(&self, id: &KeyId) -> &P::Output {
        self.stored_output.get(id).unwrap()
    }

    fn take(&mut self, id: &KeyId) -> P::Output {
        self.stored_output.remove(id).unwrap()
    }
}

/// Store participant using `Any`.
type StoredParticipant = Box<dyn Any + 'static>;

/// Generic storage for all participants.
#[derive(Default)]
struct ParticipantStorage {
    /// Map the current session ID to a participant and its key ID.
    storage: HashMap<SessionId, (StoredParticipant, KeyId)>,
}

impl ParticipantStorage {
    fn new() -> Self {
        ParticipantStorage {
            storage: Default::default(),
        }
    }

    /// Get specified participant. You must specify the `T:
    /// ProtocolParticipant`.
    fn get_mut<T: ProtocolParticipant + 'static>(
        &mut self,
        id: &SessionId,
    ) -> (&mut Participant<T>, KeyId) {
        let (dynamic, key_id) = self.storage.get_mut(id).unwrap();
        (dynamic.downcast_mut().unwrap(), *key_id)
    }

    /// Insert new participant for storage.
    fn insert<P: ProtocolParticipant + 'static>(
        &mut self,
        id: SessionId,
        participant: Participant<P>,
        key_id: KeyId,
    ) {
        self.storage.insert(id, (Box::new(participant), key_id));
    }
}

/// Message from the coordinator instructing the worker on the next action.
enum MessageFromCoordinator {
    /// Message from another worker delivering a protocol message.
    SubProtocolMessage(Message),
    /// Message from coordinator asking worker to start new subprotocol.
    NewSubProtocol(SubProtocol, KeyId, SessionId),
}

/// Maps [`ParticipantIdentifier`] to [`Sender`] channels for routing message to
/// the correct participant.
type WorkerChannels = HashMap<ParticipantIdentifier, Sender<MessageFromCoordinator>>;

/// 1) Set up logging.
/// 2) Create MPSC channels for communication between the workers and main
/// thread.
/// 3) Spawns N participant/worker threads ensuring the channels are
/// "connected" properly.
/// 4) Main thread initiates the entire [`tss_ecdsa`]
/// protocol to sign a message.
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Set up logging.
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .compact()
        .init();
    let span = span!(Level::INFO, "main");
    let _enter = span.entered();

    let num_workers = cli.number_of_workers;
    assert!(
        num_workers >= THRESHOLD,
        "Number of workers must be >= threshold {THRESHOLD}."
    );

    // Channel from workers to main thread (workers use MPSC).
    let (outgoing_tx, workers_rx) = channel::<MessageFromWorker>();
    let mut worker_messages: WorkerChannels = HashMap::new();

    // Assign a unique identifier to each participant to uniquely identify them
    // through the sub-protocols.
    let participants: Vec<ParticipantConfig> =
        ParticipantConfig::random_quorum(num_workers, &mut StdRng::from_entropy())?;
    info!("Spawning {num_workers} worker threads");

    // Spawn worker threads. Link worker to main thread with channels.
    for config in participants {
        let (from_coordinator_tx, from_coordinator_rx) = channel::<MessageFromCoordinator>();
        worker_messages.insert(config.id(), from_coordinator_tx);

        let outgoing = outgoing_tx.clone();
        thread::spawn(|| participant_worker(config, from_coordinator_rx, outgoing));
    }

    // Coordinator initiates entire protocol.
    let mut coordinator = Coordinator::new(worker_messages, workers_rx);
    coordinator.tss_ecdsa()?;

    Ok(())
}

/// Coordinator responsible for initiating sub-protocols.
///
/// **Note**: A trusted Coordinator is not required to run threshold ECDSA
/// protocol. See top-level documentation for this module for more information.
struct Coordinator {
    /// Channels to send messages to our workers.
    send_to_workers: WorkerChannels,
    /// Receive messages from worker threads to route to other workers.
    from_workers: Receiver<MessageFromWorker>,
}

impl Coordinator {
    /// Initialize `Coordinator` with the given channels for sending
    /// messages to worker threads.
    pub fn new(send_to_workers: WorkerChannels, from_workers: Receiver<MessageFromWorker>) -> Self {
        Self {
            send_to_workers,
            from_workers,
        }
    }

    /// Initiates all sub-protocols of tss-ecdsa.
    fn tss_ecdsa(&mut self) -> anyhow::Result<()> {
        let key_id = KeyId(Uuid::new_v4());
        self.initiate_sub_protocol(SubProtocol::KeyGeneration, key_id)?;
        self.initiate_sub_protocol(SubProtocol::AuxInfo, key_id)?;
        self.initiate_sub_protocol(SubProtocol::Tshare, key_id)?;
        self.initiate_sub_protocol(SubProtocol::Presign, key_id)?;
        self.initiate_sub_protocol(SubProtocol::Sign, key_id)?;

        Ok(())
    }

    /// Initiates and coordinates the specified sub-protocol from start to
    /// finish.
    fn initiate_sub_protocol(
        &mut self,
        sub_protocol: SubProtocol,
        key_id: KeyId,
    ) -> anyhow::Result<()> {
        info!(
            "Starting sub-protocol: {:?} for {:?}.",
            sub_protocol, key_id
        );

        let n_workers = self.start_new_subprotocol(sub_protocol, key_id)?;
        self.route_worker_messages(n_workers)?;

        info!("Finished sub-protocol: {:?}.", sub_protocol);
        Ok(())
    }

    /// (Helper Method) Start the specified `sub_protocol` by sending a message
    /// to all worker threads.
    fn start_new_subprotocol(
        &self,
        sub_protocol: SubProtocol,
        key_id: KeyId,
    ) -> anyhow::Result<usize> {
        let sid = SessionId(Identifier::random(&mut thread_rng()));
        let participants = self.participants(sub_protocol);

        for pid in &participants {
            let worker = self.send_to_workers.get(pid).unwrap();
            worker.send(MessageFromCoordinator::NewSubProtocol(
                sub_protocol,
                key_id,
                sid,
            ))?;
        }

        Ok(participants.len())
    }

    /// (Helper Method) Receives messages from workers via our
    /// `self.from_workers` field and routes messages to the correct worker
    /// thread via our `self.send_to_workers` map.
    ///
    /// Warning: No sender authentication is done while routing messages!
    /// This function trusts workers not to forge messages.
    fn route_worker_messages(&self, n_workers: usize) -> anyhow::Result<()> {
        // # of workers who finished the current sub_protocol.
        let mut sub_protocol_ended = 0;

        for message in &self.from_workers {
            debug!("Received messages from a worker.");

            match message {
                MessageFromWorker::FinishedRound(messages) => {
                    // Empty messages are awkward...
                    if messages.is_empty() {
                        unreachable!("We should never receive an empty message.");
                    }
                    // Forward all received messages to specified recipient.
                    for m in messages {
                        trace!("Routing message: {:?}", m);
                        let recipient = m.to();
                        self.send_to_workers
                            .get(&recipient)
                            .unwrap()
                            .send(MessageFromCoordinator::SubProtocolMessage(m))?;
                    }
                }
                MessageFromWorker::SubProtocolEnded => {
                    trace!("Worker finished sub-protocol.");
                    // TODO: Finish handling multiple in-flight sub-protocols here #382.
                    sub_protocol_ended += 1;
                    if sub_protocol_ended == n_workers {
                        debug!("All workers finished sub-protocol. Entire sub-protocol ended.");
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Select participants to a given protocol: all, or a threshold quorum.
    fn participants(&self, sub_protocol: SubProtocol) -> Vec<ParticipantIdentifier> {
        use SubProtocol::*;

        let pids = self.send_to_workers.keys().cloned().collect_vec();
        match sub_protocol {
            KeyGeneration | AuxInfo | Tshare => pids,
            Presign | Sign => threshold_participants(pids),
        }
    }
}

/// Select a threshold quorum of participants.
fn threshold_participants(mut pids: Vec<ParticipantIdentifier>) -> Vec<ParticipantIdentifier> {
    pids.sort();
    pids.truncate(THRESHOLD);
    pids
}

/// Worker participating in tss-ecdsa protocols.
struct Worker {
    /// Configuration for this participant.
    config: ParticipantConfig,
    /// Stored participants executed by this worker.
    participants: ParticipantStorage,
    /// Outputs of successful key generation.
    key_gen_material: StoredOutput<KeygenParticipant>,
    /// Outputs of successful aux info.
    aux_info: StoredOutput<AuxInfoParticipant>,
    /// Outputs of successful tshare.
    tshares: StoredOutput<TshareParticipant>,
    /// Outputs of successful presign.
    presign_records: StoredOutput<PresignParticipant>,
    /// Signatures generated from successful signing runs.
    signatures: StoredOutput<SignParticipant>,
    /// Channel for sending messages to the coordinator.
    outgoing: Sender<MessageFromWorker>,
}

impl Worker {
    /// Create new worker.
    fn new(config: ParticipantConfig, outgoing: Sender<MessageFromWorker>) -> Self {
        Worker {
            config,
            participants: ParticipantStorage::new(),
            key_gen_material: StoredOutput::new(),
            aux_info: StoredOutput::new(),
            tshares: StoredOutput::new(),
            presign_records: StoredOutput::new(),
            signatures: StoredOutput::new(),
            outgoing,
        }
    }

    /// Start a new sub-protocol. A new participant is stored in `Worker`'s
    /// internal storage.
    #[instrument(skip_all)]
    fn new_sub_protocol<P: ProtocolParticipant + 'static>(
        &mut self,
        config: ParticipantConfig,
        sid: SessionId,
        inputs: P::Input,
        key_id: KeyId,
    ) -> anyhow::Result<()> {
        let rng = &mut thread_rng();

        let mut participant: Participant<P> = Participant::from_config(config, sid.0, inputs)?;
        let init_message = participant.initialize_message()?;

        // Output will be None.
        let (_output, messages) = participant.process_single_message(&init_message, rng)?;
        self.outgoing
            .send(MessageFromWorker::FinishedRound(messages))?;
        self.participants.insert(sid, participant, key_id);

        Ok(())
    }

    // Process a message from another worker to make progress on our sub-protocol.
    //
    // This is an associated function instead of a method (does not take `self`) to
    // make borrow checker happy. As Rust cannot determine I'm borrowing
    // disjoint fields as &mut and &.
    #[instrument(skip_all)]
    fn process_message<P: ProtocolParticipant + 'static>(
        participant: &mut Participant<P>,
        key_id: KeyId,
        incoming: Message,
        stored_output: &mut StoredOutput<P>,
        outgoing: &Sender<MessageFromWorker>,
    ) -> anyhow::Result<()> {
        let (output, messages) =
            participant.process_single_message(&incoming, &mut thread_rng())?;

        // Only communicate with coordinator if we actually outputted messages.
        if !messages.is_empty() {
            outgoing.send(MessageFromWorker::FinishedRound(messages))?;
        }

        // Note: `output` is `Some(_)` only when sub-protocol is done.
        if let Some(output) = output {
            debug!("Completed subprotocol successfully. Storing outputs!");
            // Store our outputs in storage.
            stored_output.store(key_id, output);
            outgoing.send(MessageFromWorker::SubProtocolEnded)?;
        }
        Ok(())
    }
}

/// Sub-protocol wrappers around `new_sub_protocol`.
/// These functions fetch the required inputs from storage.
impl Worker {
    fn new_keygen(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        self.new_sub_protocol::<KeygenParticipant>(self.config.clone(), sid, (), key_id)
    }

    fn new_auxinfo(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        // Note: Missing inputs to aux-info see issues
        // #242 and #243.
        let _output: &Output = self.key_gen_material.retrieve(&key_id);
        self.new_sub_protocol::<AuxInfoParticipant>(self.config.clone(), sid, (), key_id)
    }

    fn new_tshare(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        let private_share = self
            .key_gen_material
            .retrieve(&key_id)
            .private_key_share()
            .try_into()?;
        let auxinfo_output = self.aux_info.retrieve(&key_id);

        let inputs = tshare::Input::new(auxinfo_output.clone(), Some(private_share), THRESHOLD)?;
        self.new_sub_protocol::<TshareParticipant>(self.config.clone(), sid, inputs, key_id)
    }

    /// Pick a quorum of participants. Return the corresponding additive shares.
    fn make_quorum(
        &self,
        key_id: KeyId,
    ) -> anyhow::Result<(ParticipantConfig, keygen::Output, auxinfo::Output)> {
        let participants = threshold_participants(self.config.all_participants());

        let keygen_output = self.key_gen_material.retrieve(&key_id);
        let tshare_output = self.tshares.retrieve(&key_id);

        let config = self.config.filter_participants(&participants);

        let auxinfo_quorum = self
            .aux_info
            .retrieve(&key_id)
            .filter_participants(&participants);

        let keygen_quorum = TshareParticipant::convert_to_t_out_of_t_share(
            &config,
            tshare_output,
            *keygen_output.rid(),
            *keygen_output.chain_code(),
        )?;

        Ok((config, keygen_quorum, auxinfo_quorum))
    }

    fn new_presign(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        let (config, keygen_quorum, auxinfo_quorum) = self.make_quorum(key_id)?;

        let inputs = presign::Input::new(auxinfo_quorum, keygen_quorum)?;
        self.new_sub_protocol::<PresignParticipant>(config, sid, inputs, key_id)
    }

    fn new_sign(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        let (config, keygen_quorum, _) = self.make_quorum(key_id)?;
        let key_shares = keygen_quorum.public_key_shares();
        let record = self.presign_records.take(&key_id);

        let inputs = sign::Input::new(b"hello world", record, key_shares.to_vec(), THRESHOLD, None);
        self.new_sub_protocol::<SignParticipant>(config, sid, inputs, key_id)
    }
}

/// Sub-protocol wrappers around `process_message` method.
impl Worker {
    fn process_keygen(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        let (p, key_id) = self.participants.get_mut::<KeygenParticipant>(&sid);
        Self::process_message(
            p,
            key_id,
            incoming,
            &mut self.key_gen_material,
            &self.outgoing,
        )
    }

    fn process_auxinfo(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        let (p, key_id) = self.participants.get_mut::<AuxInfoParticipant>(&sid);
        Self::process_message(p, key_id, incoming, &mut self.aux_info, &self.outgoing)
    }

    fn process_tshare(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        let (p, key_id) = self.participants.get_mut::<TshareParticipant>(&sid);
        Self::process_message(p, key_id, incoming, &mut self.tshares, &self.outgoing)
    }

    fn process_presign(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        let (p, key_id) = self.participants.get_mut::<PresignParticipant>(&sid);
        Self::process_message(
            p,
            key_id,
            incoming,
            &mut self.presign_records,
            &self.outgoing,
        )
    }

    fn process_sign(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        let (p, key_id) = self.participants.get_mut::<SignParticipant>(&sid);
        Self::process_message(p, key_id, incoming, &mut self.signatures, &self.outgoing)
    }
}

/// Function to drive work for the workers. These workers execute in their
/// own thread.
#[instrument(skip_all)]
fn participant_worker(
    config: ParticipantConfig,
    from_coordinator: Receiver<MessageFromCoordinator>,
    outgoing: Sender<MessageFromWorker>,
) -> anyhow::Result<()> {
    info!("Worker thread started.");
    let mut worker = Worker::new(config, outgoing);
    let mut current_subprotocol: HashMap<SessionId, SubProtocol> = Default::default();

    for incoming in from_coordinator {
        match incoming {
            // Message from another worker for a current protocol we are executing.
            MessageFromCoordinator::SubProtocolMessage(message) => {
                let sid = SessionId(message.id());
                let sub_protocol = current_subprotocol.get(&sid).unwrap();

                match sub_protocol {
                    SubProtocol::KeyGeneration => {
                        worker.process_keygen(sid, message)?;
                    }
                    SubProtocol::AuxInfo => {
                        worker.process_auxinfo(sid, message)?;
                    }
                    SubProtocol::Tshare => {
                        worker.process_tshare(sid, message)?;
                    }
                    SubProtocol::Presign => worker.process_presign(sid, message)?,
                    SubProtocol::Sign => worker.process_sign(sid, message)?,
                }
            }
            // Message from coordinator asking us to start a new sub-protocol.
            MessageFromCoordinator::NewSubProtocol(sub_protocol, key_id, sid) => {
                current_subprotocol.insert(sid, sub_protocol);

                match sub_protocol {
                    SubProtocol::KeyGeneration => {
                        worker.new_keygen(sid, key_id)?;
                    }
                    SubProtocol::AuxInfo => {
                        worker.new_auxinfo(sid, key_id)?;
                    }
                    SubProtocol::Tshare => {
                        worker.new_tshare(sid, key_id)?;
                    }
                    SubProtocol::Presign => {
                        worker.new_presign(sid, key_id)?;
                    }
                    SubProtocol::Sign => {
                        worker.new_sign(sid, key_id)?;
                    }
                }
            }
        }
    }

    Ok(())
}
