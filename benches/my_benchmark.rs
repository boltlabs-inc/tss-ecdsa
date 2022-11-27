use criterion::{criterion_group, criterion_main, Criterion};

use rand::{prelude::IteratorRandom, rngs::OsRng, CryptoRng, Rng, RngCore};
use std::collections::HashMap;
use tss_ecdsa::{errors::Result, Identifier, Message, Participant, ParticipantIdentifier};
/// Delivers all messages into their respective participant's inboxes
fn deliver_all(
    messages: &[Message],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> Result<()> {
    for message in messages {
        for (&id, inbox) in &mut *inboxes {
            if id == message.to() {
                inbox.push(message.clone());
                break;
            }
        }
    }
    Ok(())
}

fn is_keygen_done(quorum: &[Participant], keygen_identifier: Identifier) -> bool {
    for participant in quorum {
        if participant.is_keygen_done(keygen_identifier).is_err() {
            return false;
        }
    }
    true
}

fn is_auxinfo_done(quorum: &[Participant], auxinfo_identifier: Identifier) -> bool {
    for participant in quorum {
        if participant.is_auxinfo_done(auxinfo_identifier).is_err() {
            return false;
        }
    }
    true
}

fn is_presigning_done(quorum: &[Participant], presign_identifier: Identifier) -> bool {
    for participant in quorum {
        if participant.is_presigning_done(presign_identifier).is_err() {
            return false;
        }
    }
    true
}

fn process_messages<R: RngCore + CryptoRng>(
    quorum: &mut [Participant],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut R,
) -> Result<()> {
    // Pick a random participant to process
    let participant = quorum.iter_mut().choose(rng).unwrap();

    let inbox = inboxes.get_mut(&participant.id).unwrap();
    if inbox.is_empty() {
        // No messages to process for this participant, so pick another participant
        return Ok(());
    }

    // Process a random message in the participant's inbox
    // This is done to simulate arbitrary message arrival ordering
    let index = rng.gen_range(0..inbox.len());
    let message = inbox.remove(index);
    let messages = participant.process_single_message(&message, rng)?;
    deliver_all(&messages, inboxes)?;

    Ok(())
}

fn run_keygen(
    quorum: &mut [Participant],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    keygen_identifier: Identifier,
) -> Result<()> {
    let mut rng = OsRng;
    for participant in quorum.iter() {
        let inbox = inboxes.get_mut(&participant.id).unwrap();
        inbox.push(participant.initialize_keygen_message(keygen_identifier));
    }
    while !is_keygen_done(quorum, keygen_identifier) {
        process_messages(quorum, inboxes, &mut rng)?;
    }
    Ok(())
}

fn run_auxinfo(
    quorum: &mut [Participant],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    auxinfo_identifier: Identifier,
) -> Result<()> {
    let mut rng = OsRng;
    for participant in quorum.iter() {
        let inbox = inboxes.get_mut(&participant.id).unwrap();
        inbox.push(participant.initialize_auxinfo_message(auxinfo_identifier));
    }
    while !is_auxinfo_done(quorum, auxinfo_identifier) {
        process_messages(quorum, inboxes, &mut rng)?;
    }
    Ok(())
}

fn run_presign(
    quorum: &mut [Participant],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    auxinfo_identifier: Identifier,
    keygen_identifier: Identifier,
    presign_identifier: Identifier,
) -> Result<()> {
    let mut rng = OsRng;
    for participant in quorum.iter_mut() {
        let inbox = inboxes.get_mut(&participant.id).unwrap();
        inbox.push(participant.initialize_presign_message(
            auxinfo_identifier,
            keygen_identifier,
            presign_identifier,
        )?);
    }
    while !is_presigning_done(quorum, presign_identifier) {
        process_messages(quorum, inboxes, &mut rng)?;
    }
    Ok(())
}

fn init_new_player_set(
    num_players: usize,
) -> (
    Vec<Participant>,
    HashMap<ParticipantIdentifier, Vec<Message>>,
) {
    let mut rng = OsRng;
    let quorum = Participant::new_quorum(num_players, &mut rng).unwrap();
    let mut inboxes = HashMap::new();
    for participant in &quorum {
        let _ = inboxes.insert(participant.id, vec![]);
    }
    (quorum, inboxes)
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = OsRng;
    let (mut players_3, mut inboxes_3) = init_new_player_set(3);
    let (mut players_10, mut inboxes_10) = init_new_player_set(10);
    let (mut players_20, mut inboxes_20) = init_new_player_set(20);

    let keygen_identifier = Identifier::random(&mut rng);
    // Use cloned values for the quorum and inboxes to keep runs independent
    c.bench_function("Keygen with 3 nodes", |b| {
        b.iter(|| {
            run_keygen(
                &mut players_3.clone(),
                &mut inboxes_3.clone(),
                keygen_identifier,
            )
        })
    });
    c.bench_function("Keygen with 10 nodes", |b| {
        b.iter(|| {
            run_keygen(
                &mut players_10.clone(),
                &mut inboxes_10.clone(),
                keygen_identifier,
            )
        })
    });
    c.bench_function("Keygen with 20 nodes", |b| {
        b.iter(|| {
            run_keygen(
                &mut players_20.clone(),
                &mut inboxes_20.clone(),
                keygen_identifier,
            )
        })
    });

    let auxinfo_identifier = Identifier::random(&mut rng);
    c.bench_function("Auxinfo with 3 nodes", |b| {
        b.iter(|| {
            run_auxinfo(
                &mut players_3.clone(),
                &mut inboxes_3.clone(),
                auxinfo_identifier,
            )
        })
    });
    c.bench_function("Auxinfo with 10 nodes", |b| {
        b.iter(|| {
            run_auxinfo(
                &mut players_10.clone(),
                &mut inboxes_10.clone(),
                auxinfo_identifier,
            )
        })
    });
    c.bench_function("Auxinfo with 20 nodes", |b| {
        b.iter(|| {
            run_auxinfo(
                &mut players_20.clone(),
                &mut inboxes_20.clone(),
                auxinfo_identifier,
            )
        })
    });

    // Presign needs Keygen and Auxinfo to be completed before it can run,
    // so we run those first
    run_keygen(&mut players_3, &mut inboxes_3, keygen_identifier).unwrap();
    run_keygen(&mut players_10, &mut inboxes_10, keygen_identifier).unwrap();
    run_keygen(&mut players_20, &mut inboxes_20, keygen_identifier).unwrap();
    run_auxinfo(&mut players_3, &mut inboxes_3, auxinfo_identifier).unwrap();
    run_auxinfo(&mut players_10, &mut inboxes_10, auxinfo_identifier).unwrap();
    run_auxinfo(&mut players_20, &mut inboxes_20, auxinfo_identifier).unwrap();

    let presign_identifier = Identifier::random(&mut rng);
    c.bench_function("Presign with 3 nodes", |b| {
        b.iter(|| {
            run_presign(
                &mut players_3.clone(),
                &mut inboxes_3.clone(),
                auxinfo_identifier,
                keygen_identifier,
                presign_identifier,
            )
        })
    });
    c.bench_function("Presign with 10 nodes", |b| {
        b.iter(|| {
            run_presign(
                &mut players_10.clone(),
                &mut inboxes_10.clone(),
                auxinfo_identifier,
                keygen_identifier,
                presign_identifier,
            )
        })
    });
    c.bench_function("Presign with 20 nodes", |b| {
        b.iter(|| {
            run_presign(
                &mut players_20.clone(),
                &mut inboxes_20.clone(),
                auxinfo_identifier,
                keygen_identifier,
                presign_identifier,
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
