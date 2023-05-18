//! Example usage of [`tss_ecdsa`] crate.
//!
//! Each [`Participant`] is represented by a worker thread. This example uses
//! [`std::sync::mpsc`] channels to communicate [`Message`]s
//! amongst threads.

use anyhow::{self};
use clap::Parser;
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};
use tracing::{debug, info, instrument, span, trace, Level};
use tracing_subscriber::{self, EnvFilter};
use tss_ecdsa::{
    keygen, AuxInfoParticipant, AuxInfoPrivate, AuxInfoPublic, Identifier, KeygenParticipant,
    Message, Participant, ParticipantConfig, ParticipantIdentifier, PresignInput,
    PresignParticipant, PresignRecord, ProtocolParticipant,
};

/// Messages from main thread to Participant worker threads.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
enum SubProtocol {
    KeyGeneration,
    AuxInfo,
    Presign,
    Sign,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CommandLineArgs {
    /// Number of participant worker threads to use.
    #[arg(short, long)]
    number_of_workers: usize,
    /// Number of times to perform each sub-protocol of tss-ecdsa.
    /// protocol_executions > 1 useful for computing meaningful average
    /// execution times.
    #[arg(short, long)]
    protocol_executions: usize,
}

/// Outgoing message from worker threads to main thread.
#[derive(Debug)]
enum MessageFromWorker {
    /// Worker made progress on sub-protocol, returning some messages.
    FinishedRound(Vec<Message>),
    /// Current sub-protocol ended.
    SubProtocolEnded,
}

/// Maps [`ParticipantIdentifier`] to [`Sender`] channels for routing message to
/// the correct participant.
type WorkerChannels = HashMap<ParticipantIdentifier, Sender<Message>>;
/// Channels for informing workers of the next [`SubProtocol`] to perform with
/// the given SID [`Identifier`].
type NextActionChannels = Vec<Sender<(SubProtocol, Identifier)>>;

/// 1) Set up logging.
/// 2) Create MPSC channels for communication between the workers and main
/// thread.
/// 3) Spawns N participant/worker threads ensuring the channels are
/// "connected" properly.
/// 4) Main thread executes the entire [`tss_ecdsa`]
/// protocol to sign a message.
fn main() -> anyhow::Result<()> {
    let cli = CommandLineArgs::parse();
    // Set up logging.
    let filter = EnvFilter::from_default_env().add_directive("threaded_example=info".parse()?);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .compact()
        .init();
    let span = span!(Level::INFO, "main");
    let _enter = span.entered();

    let num_workers = cli.number_of_workers;
    let rng = &mut StdRng::from_entropy();

    // Channel from workers to main thread (workers use MPSC).
    let (outgoing_tx, workers_rx) = channel::<MessageFromWorker>();
    let mut worker_messages: WorkerChannels = HashMap::new();
    let mut next_action: NextActionChannels = Vec::new();

    // Assign a unique identifier to each participant to uniquely identify them
    // through the sub-protocols.
    let mut participants: Vec<ParticipantConfig> =
        ParticipantConfig::random_quorum(num_workers, rng)?;
    info!("Spawning {num_workers} worker threads");

    // Spawn worker threads. Link worker to main thread with channels.
    for _ in 0..num_workers {
        // Create per-thread channels.
        let config = participants.pop().unwrap();

        // Channels for sending/receiving sub-protocol [`Message`]s to/from main thread.
        let (worker_message_tx, worker_message_rx) = channel::<Message>();
        // Main thread uses this channel to inform worker of next sub-protocol to
        // execute.
        let (next_action_tx, next_action_rx) = channel::<(SubProtocol, Identifier)>();
        next_action.push(next_action_tx);
        worker_messages.insert(config.id, worker_message_tx);

        let outgoing = outgoing_tx.clone();
        thread::spawn(|| participant_worker(config, next_action_rx, worker_message_rx, outgoing));
    }

    // Main thread executes entire protocol.
    let runner = SubProtocolRunner::new(worker_messages, next_action, workers_rx, num_workers);
    do_tss_ecdsa(runner, cli.protocol_executions)?;

    Ok(())
}

/// Gathers statistics about execution time of each sub-protocol.
struct Statistics {
    /// Saves the execution time ([`Duration`]) of executing each sub-protocol.
    execution_time: HashMap<SubProtocol, Vec<Duration>>,
}

impl Statistics {
    /// Initialize.
    pub fn new() -> Self {
        // Pre-populate.
        let mut execution_time = HashMap::new();
        execution_time.insert(SubProtocol::KeyGeneration, Vec::new());
        execution_time.insert(SubProtocol::AuxInfo, Vec::new());
        execution_time.insert(SubProtocol::Presign, Vec::new());
        execution_time.insert(SubProtocol::Sign, Vec::new());

        Self { execution_time }
    }

    /// Add a new `Duration` data point for the given `sub_protocol`.
    fn record(&mut self, sub_protocol: SubProtocol, duration: Duration) {
        let execution_times = self.execution_time.get_mut(&sub_protocol).unwrap();
        execution_times.push(duration);
    }

    /// Compute the average execution time for the given `sub_protocol`. Returns
    /// the average execution time along with the number of data points.
    fn average_execution_time(&self, sub_protocol: SubProtocol) -> (Duration, u32) {
        let times = self.execution_time.get(&sub_protocol).unwrap();
        let mut total = Duration::from_secs(0);
        for t in times {
            total += *t;
        }

        let count = times.len() as u32;
        (total / count, count)
    }
}

/// Runs the specified function `f`, returning either an error (if `f` failed)
/// or the execution time of `f`.
fn measure<T>(mut f: impl FnMut() -> anyhow::Result<T>) -> anyhow::Result<Duration> {
    let now = Instant::now();
    f()?;
    Ok(now.elapsed())
}

/// Helper type for running sub-protocols.
struct SubProtocolRunner {
    /// Channels for routing specific `Message`s to a given worker/participant.
    send_to_workers: WorkerChannels,
    /// Next sub-protocol all worker threads should execute.
    next_action: NextActionChannels,
    /// Receive messages from worker threads to route to other workers.
    from_workers: Receiver<MessageFromWorker>,
    /// Total number of Participants/worker threads participating in our
    /// sub-protocol.
    total_workers: usize,
    /// Execution time data gathered during execution.
    statistics: Statistics,
}

impl SubProtocolRunner {
    /// Initialize `SubProtocolRunner` with the given channels for sending
    /// messages to worker threads.
    pub fn new(
        send_to_workers: WorkerChannels,
        next_action: NextActionChannels,
        from_workers: Receiver<MessageFromWorker>,
        total_workers: usize,
    ) -> Self {
        Self {
            send_to_workers,
            next_action,
            from_workers,
            total_workers,
            statistics: Statistics::new(),
        }
    }

    /// Runs an entire sub-protocol from start to end. Records statistics about
    /// sub-protocol execution time from main thread's point of view.
    fn do_sub_protocol(&mut self, sub_protocol: SubProtocol) -> anyhow::Result<()> {
        info!("Starting sub-protocol: {:?}.", sub_protocol);
        let duration = measure(|| {
            self.start_subprotocol(sub_protocol)?;
            self.route_worker_messages()?;
            Ok(())
        })?;
        self.record(sub_protocol, duration);

        info!("Finished sub-protocol: {:?}.", sub_protocol);
        Ok(())
    }

    /// (Helper Method) Start the specified `sub_protocol` by sending a message
    /// to all worker threads.
    fn start_subprotocol(&self, sub_protocol: SubProtocol) -> anyhow::Result<()> {
        debug!("Starting sub-protocol: {:?}", sub_protocol);
        let rng = &mut thread_rng();
        let sid = Identifier::random(rng);

        for worker in &self.next_action {
            worker.send((sub_protocol, sid))?;
        }

        Ok(())
    }

    /// (Helper Method) Receives messages from workers via our
    /// `self.from_workers` field and routes messages to the correct worker
    /// thread via our `self.send_to_workers` map.
    fn route_worker_messages(&self) -> anyhow::Result<()> {
        // # of workers who finished the current sub_protocol.
        let mut sub_protocol_ended = 0;

        for message in &self.from_workers {
            debug!("Received messages from a worker.");

            match message {
                MessageFromWorker::FinishedRound(messages) => {
                    // Empty messages are awkward...
                    if messages.is_empty() {
                        trace!("Received empty messages...");
                    }
                    for m in messages {
                        trace!("Routing message: {:?}", m);
                        let recipient = m.to();
                        self.send_to_workers.get(&recipient).unwrap().send(m)?;
                    }
                }
                MessageFromWorker::SubProtocolEnded => {
                    trace!("Worker finished sub-protocol.");
                    sub_protocol_ended += 1;
                    if sub_protocol_ended == self.total_workers {
                        debug!("All workers finished sub-protocol. Entire sub-protocol ended.");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a new `Duration` data point for the given `sub_protocol`.
    fn record(&mut self, sub_protocol: SubProtocol, duration: Duration) {
        self.statistics.record(sub_protocol, duration);
    }
}

/// Execute each sub-protocol of tss-ecdsa.
///
/// Prints average execution time to the log.
fn do_tss_ecdsa(mut runner: SubProtocolRunner, execution_times: usize) -> anyhow::Result<()> {
    info!("Starting key generation.");
    let runner = &mut runner;

    for i in 0..execution_times {
        info!("Running all sub-protocols. ({i}/{execution_times}).");
        runner.do_sub_protocol(SubProtocol::KeyGeneration)?;
        runner.do_sub_protocol(SubProtocol::AuxInfo)?;
        runner.do_sub_protocol(SubProtocol::Presign)?;
        runner.do_sub_protocol(SubProtocol::Sign)?;
    }

    let (time, count) = runner
        .statistics
        .average_execution_time(SubProtocol::KeyGeneration);
    info!(
        "Finished key generation. Average from {} runs: {}us",
        count,
        time.as_micros()
    );
    let (time, count) = runner
        .statistics
        .average_execution_time(SubProtocol::AuxInfo);
    info!(
        "Finished key generation. Average from {} runs: {}s",
        count,
        time.as_secs()
    );
    let (time, count) = runner
        .statistics
        .average_execution_time(SubProtocol::Presign);
    info!(
        "Finished presign. Average from {} runs: {}ms",
        count,
        time.as_millis()
    );
    let (time, count) = runner.statistics.average_execution_time(SubProtocol::Sign);
    info!(
        "Finished sign. Average from {} runs: {}us",
        count,
        time.as_micros()
    );

    Ok(())
}

/// Main function executed by each worker thread.
/// Waits for main thread to specify the `next_action` (which sub-protocol to
/// execute next) and executes it. Saves sub-protocol output to a local variable
/// for use in subsequent sub-protocols.
///
/// Note: This function only handles a protocol session. Successive sub-protocol
/// calls will overwrite output values of previous sub-protocol.
#[instrument(skip_all)]
fn participant_worker(
    config: ParticipantConfig,
    next_action: Receiver<(SubProtocol, Identifier)>,
    other_workers: Receiver<Message>,
    outgoing: Sender<MessageFromWorker>,
) -> anyhow::Result<()> {
    info!("Worker thread started.");

    // Outputs of our sub-protocols. These variable are set when a sub-protocol is
    // finished executing.
    let mut keygen_output: Option<keygen::Output> = None;
    let mut aux_info_public: Option<Vec<AuxInfoPublic>> = None;
    let mut aux_info_private: Option<AuxInfoPrivate> = None;
    let mut presign_record: Option<PresignRecord> = None;

    // Listen for next sub-protocol to execute.
    // Each sub-protocol follows the same pattern:
    // 1) Instantiate a `participant` with the inputs required for that
    // sub-protocol. 2) Call `worker_handle_subprotocol`
    // 3) Save any outputs produced by the sub-protocol.
    for (sub_protocol, sid) in next_action {
        match sub_protocol {
            SubProtocol::KeyGeneration => {
                let participant: Participant<KeygenParticipant> =
                    // Keygen requires no sub-protocol specific inputs, hence `()`.
                    Participant::from_config(&config, sid, ())?;
                let keygen_output_local =
                    worker_handle_subprotocol(participant, &other_workers, &outgoing)?;

                keygen_output = Some(keygen_output_local);

                outgoing.send(MessageFromWorker::SubProtocolEnded)?;
            }
            SubProtocol::AuxInfo => {
                let participant: Participant<AuxInfoParticipant> =
                    // Note: Missing inputs to aux-info see issues #242 and #243.
                    Participant::from_config(&config, sid, ())?;

                let (aux_info_public_local, aux_info_private_local) =
                    worker_handle_subprotocol(participant, &other_workers, &outgoing)?;

                aux_info_public = Some(aux_info_public_local);
                aux_info_private = Some(aux_info_private_local);

                outgoing.send(MessageFromWorker::SubProtocolEnded)?;
            }
            SubProtocol::Presign => {
                let input: PresignInput = PresignInput::new(
                    aux_info_public.clone().unwrap(),
                    aux_info_private.clone().unwrap(),
                    keygen_output.clone().unwrap(),
                )?;
                let participant: Participant<PresignParticipant> =
                    Participant::from_config(&config, sid, input)?;
                let presign_record_local =
                    worker_handle_subprotocol(participant, &other_workers, &outgoing)?;
                presign_record = Some(presign_record_local);

                outgoing.send(MessageFromWorker::SubProtocolEnded)?;
            }
            SubProtocol::Sign => {
                let signature = presign_record.take().unwrap().sign(message_to_sign())?;
                info!("Computed signature: {:?}", signature);
                outgoing.send(MessageFromWorker::SubProtocolEnded)?;
            }
        }
    }

    Ok(())
}

fn message_to_sign() -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"hello world");
    hasher
}

/// This function drives execution of a sub-protocol from start to finish:
/// 1) Initialize the `participant`.
/// 2) Loop doing:
/// 3) Send out messages generated by sub-protocol round.
/// 4) Receive and process messages from other workers.
/// 5) Return outputs of sub-protocol.
#[instrument(skip_all)]
fn worker_handle_subprotocol<P: ProtocolParticipant>(
    mut participant: Participant<P>,
    incoming: &Receiver<Message>,
    outgoing: &Sender<MessageFromWorker>,
) -> anyhow::Result<P::Output> {
    let rng = &mut thread_rng();

    debug!("Starting sub-protocol.");
    let init_message = participant.initialize_message();

    let (output, messages) = participant.process_single_message(&init_message, rng)?;
    assert!(output.is_none());
    outgoing.send(MessageFromWorker::FinishedRound(messages))?;

    for m in incoming {
        trace!("Received message from another worker.");
        let (output, messages) = participant.process_single_message(&m, rng)?;
        outgoing.send(MessageFromWorker::FinishedRound(messages))?;

        // Note: `output` is `Some(_)` only when sub-protocol is done.
        if let Some(output) = output {
            debug!("Completed successfully!");
            return Ok(output);
        }
    }

    unreachable!()
}
