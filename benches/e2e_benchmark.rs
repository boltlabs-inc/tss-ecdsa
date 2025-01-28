use criterion::{criterion_group, criterion_main, Criterion};

use rand::{prelude::IteratorRandom, rngs::OsRng, CryptoRng, Rng, RngCore};
use std::collections::HashMap;
use tss_ecdsa::{
    auxinfo::AuxInfoParticipant,
    curve::TestCurve,
    errors::Result,
    keygen::KeygenParticipant,
    messages::Message,
    presign::{self, PresignParticipant},
    Identifier, Participant, ParticipantConfig, ParticipantIdentifier, ProtocolParticipant,
};

/// Delivers all messages into their respective participant's inboxes
fn deliver_all(messages: &[Message], inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>) {
    for message in messages {
        inboxes
            .get_mut(&message.to())
            .unwrap()
            .push(message.clone());
    }
}

/// Process a single message for a single participant, randomly chosen. If that
/// participant completes the protocol, return their output.
fn process_messages<R: RngCore + CryptoRng, P: ProtocolParticipant>(
    quorum: &mut [Participant<P>],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut R,
) -> Result<Option<P::Output>> {
    // Pick a random participant to process
    let participant = quorum.iter_mut().choose(rng).unwrap();

    let inbox = inboxes.get_mut(&participant.id()).unwrap();
    if inbox.is_empty() {
        // No messages to process for this participant, so pick another participant
        return Ok(None);
    }

    // Process a random message in the participant's inbox
    // This is done to simulate arbitrary message arrival ordering
    let index = rng.gen_range(0..inbox.len());
    let message = inbox.remove(index);
    let (output, messages) = participant.process_single_message(&message, rng)?;
    deliver_all(&messages, inboxes);

    Ok(output)
}

fn run_subprotocol<P: ProtocolParticipant>(
    sid: Identifier,
    inputs: Vec<P::Input>,
) -> Result<Vec<P::Output>> {
    let (mut quorum, mut inboxes) = init_new_player_set::<P>(sid, inputs);

    let mut rng = rand::thread_rng();
    for participant in quorum.iter() {
        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        inbox.push(participant.initialize_message()?);
    }

    let mut outputs = Vec::with_capacity(quorum.len());
    while outputs.len() < quorum.len() {
        if let Some(output) = process_messages(&mut quorum, &mut inboxes, &mut rng)? {
            outputs.push(output)
        }
    }
    Ok(outputs)
}

fn init_new_player_set<P: ProtocolParticipant>(
    sid: Identifier,
    inputs: Vec<P::Input>,
) -> (
    Vec<Participant<P>>,
    HashMap<ParticipantIdentifier, Vec<Message>>,
) {
    let mut rng = rand::thread_rng();
    let num_players = inputs.len();

    // Get the sets of mine/other ids for each party
    let configs = ParticipantConfig::random_quorum(num_players, &mut rng).unwrap();

    // Instantiate participants
    let quorum: Vec<Participant<P>> = configs
        .into_iter()
        .zip(inputs)
        .map(|(config, input)| Participant::from_config(config, sid, input).unwrap())
        .collect();

    // Instantiate inboxes
    let mut inboxes = HashMap::new();
    for participant in &quorum {
        let _ = inboxes.insert(participant.id(), vec![]);
    }
    (quorum, inboxes)
}

fn run_benchmarks_for_given_size(c: &mut Criterion, num_players: usize) {
    let mut rng = OsRng;

    // Note: Inboxes and participants are created in the `run_subprotocol` method,
    // so we're sadly benchmarking the time it takes to do that generation.

    // Benchmark keygen
    let keygen_sid = Identifier::random(&mut rng);
    let keygen_inputs = std::iter::repeat(()).take(num_players).collect::<Vec<_>>();
    c.bench_function(&format!("Keygen with {num_players} nodes"), |b| {
        b.iter(|| {
            run_subprotocol::<KeygenParticipant<TestCurve>>(keygen_sid, keygen_inputs.clone())
        })
    });

    // Benchmark auxinfo
    let auxinfo_sid = Identifier::random(&mut rng);
    let auxinfo_inputs = std::iter::repeat(()).take(num_players).collect::<Vec<_>>();
    c.bench_function(&format!("Auxinfo with {num_players} nodes"), |b| {
        b.iter(|| {
            run_subprotocol::<AuxInfoParticipant<TestCurve>>(auxinfo_sid, auxinfo_inputs.clone())
        })
    });

    // Prepare to benchmark presign:
    // 1. Run keygen and get outputs
    let keygen_inputs = std::iter::repeat(()).take(num_players).collect();
    let keygen_outputs =
        run_subprotocol::<KeygenParticipant<TestCurve>>(keygen_sid, keygen_inputs).unwrap();

    // 2. Run auxinfo and get outputs
    let auxinfo_inputs = std::iter::repeat(()).take(num_players).collect();
    let auxinfo_outputs =
        run_subprotocol::<AuxInfoParticipant<TestCurve>>(auxinfo_sid, auxinfo_inputs).unwrap();

    // 3. Assemble presign input from keygen and auxinfo.
    let presign_inputs = auxinfo_outputs
        .into_iter()
        .zip(keygen_outputs)
        .map(|(auxinfo_output, keygen_output)| {
            presign::Input::new(auxinfo_output, keygen_output).unwrap()
        })
        .collect::<Vec<_>>();

    // Benchmark presign
    let presign_identifier = Identifier::random(&mut rng);
    c.bench_function(&format!("Presign with {num_players} nodes"), |b| {
        b.iter(|| {
            run_subprotocol::<PresignParticipant<TestCurve>>(
                presign_identifier,
                presign_inputs.clone(),
            )
        })
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    run_benchmarks_for_given_size(c, 3);
    run_benchmarks_for_given_size(c, 6);
    run_benchmarks_for_given_size(c, 9);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
