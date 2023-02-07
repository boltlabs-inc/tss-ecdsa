// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::common::{Args, ErrorWrapper, ParticipantInitConfig, Result};
use rand::rngs::OsRng;
use rocket::{data::ToByteUnit, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Notify, RwLock};
use tss_ecdsa::{CurvePoint, Identifier, Message, Participant};

pub(crate) struct ParticipantState {
    init_config: RwLock<Option<ParticipantInitConfig>>,
    participant: RwLock<Option<Participant>>,
    auxinfo_notifications: RwLock<HashMap<Identifier, Arc<Notify>>>,
    keygen_notifications: RwLock<HashMap<Identifier, Arc<Notify>>>,
    presign_notifications: RwLock<HashMap<Identifier, Arc<Notify>>>,
}

pub(crate) async fn server_main(args: Args) -> Result {
    let figment = rocket::Config::figment().merge(("port", args.port)).merge((
        "limits",
        rocket::data::Limits::new()
            .limit("bytes", 100.megabytes())
            .limit("json", 100.megabytes()),
    ));

    let empty_state = ParticipantState {
        init_config: RwLock::new(None),
        participant: RwLock::new(None),
        auxinfo_notifications: RwLock::new(HashMap::new()),
        keygen_notifications: RwLock::new(HashMap::new()),
        presign_notifications: RwLock::new(HashMap::new()),
    };

    let _rocket = rocket::custom(figment)
        .mount(
            "/",
            routes![
                process,
                initialize,
                auxinfo,
                keygen,
                presign,
                sign_from_presign
            ],
        )
        .manage(empty_state)
        .launch()
        .await?;

    Ok(())
}

#[post("/initialize", data = "<config_bytes>")]
pub(crate) async fn initialize(state: &State<ParticipantState>, config_bytes: Vec<u8>) -> Result {
    let input: ParticipantInitConfig = bincode::deserialize(&config_bytes)?;

    let mut init_config = state.init_config.write().await;
    *init_config = Some(input.clone());
    drop(init_config);

    let mut participant = state.participant.write().await;
    *participant = Some(Participant::from_config(input.config)?);
    drop(participant);

    Ok(())
}

/// Processes a single message, and sends out a bunch of other messages
#[post("/process", data = "<message_bytes>")]
pub(crate) async fn process(state: &State<ParticipantState>, message_bytes: Vec<u8>) -> Result {
    let message: Message = bincode::deserialize(&message_bytes)?;

    let mut state_participant = state.participant.write().await;
    let mut participant = (*state_participant)
        .clone()
        .ok_or_else(|| anyhow!("Config not set"))?;

    let mut rng = OsRng;
    let messages = participant.process_single_message(&message, &mut rng)?;

    *state_participant = Some(participant.clone());
    drop(state_participant); // Release the lock

    // Deliver messages to other participants
    let client = reqwest::Client::new();
    let ids_to_ports = {
        let init_config = state.init_config.read().await;
        (*init_config).clone().unwrap().ids_to_ports
    };
    for message in messages {
        let port = ids_to_ports.get(&message.to()).unwrap();
        let request = client
            .post(format!("http://127.0.0.1:{port}/process/"))
            .body(bincode::serialize(&message).unwrap())
            .send();

        tokio::spawn(async move { request.await });
    }

    // Ping notifications if protocol was completed

    let auxinfo_notifications = state.auxinfo_notifications.read().await;
    if auxinfo_notifications.contains_key(&message.id())
        && participant.is_auxinfo_done(message.id()).unwrap()
    {
        let notify = auxinfo_notifications.get(&message.id()).unwrap().clone();
        notify.notify_one();
    }
    drop(auxinfo_notifications);

    let keygen_notifications = state.keygen_notifications.read().await;
    if keygen_notifications.contains_key(&message.id())
        && participant.is_keygen_done(message.id()).unwrap()
    {
        let notify = keygen_notifications.get(&message.id()).unwrap().clone();
        notify.notify_one();
    }
    drop(keygen_notifications);

    let presign_notifications = state.presign_notifications.read().await;
    if presign_notifications.contains_key(&message.id())
        && participant.is_presigning_done(message.id()).unwrap()
    {
        let notify = presign_notifications.get(&message.id()).unwrap().clone();
        notify.notify_one();
    }
    drop(presign_notifications);

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AuxInfoParameters {
    pub(crate) auxinfo_identifier: Identifier,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeygenParameters {
    pub(crate) auxinfo_identifier: Identifier,
    pub(crate) keygen_identifier: Identifier,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PresignParameters {
    pub(crate) auxinfo_identifier: Identifier,
    pub(crate) keygen_identifier: Identifier,
    pub(crate) presign_identifier: Identifier,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SignFromPresignParameters {
    pub(crate) presign_identifier: Identifier,
    pub(crate) input: Vec<u8>,
}

#[post("/auxinfo", data = "<parameters>")]
async fn auxinfo(state: &State<ParticipantState>, parameters: Json<AuxInfoParameters>) -> Result {
    let auxinfo_identifier = parameters.auxinfo_identifier;

    let participant = {
        let state_participant = state.participant.read().await;
        (*state_participant)
            .clone()
            .ok_or_else(|| anyhow!("Config not set"))?
    };
    let message = participant.initialize_auxinfo_message(auxinfo_identifier);

    // Create new notification for this auxinfo identifier
    let mut state_notifications = state.auxinfo_notifications.write().await;
    state_notifications.insert(auxinfo_identifier, Arc::new(Notify::new()));
    drop(state_notifications);

    process(state, bincode::serialize(&message)?).await?;

    // Block until operation is done from process()
    let notify = {
        let notifications = state.auxinfo_notifications.read().await;
        notifications.get(&auxinfo_identifier).unwrap().clone()
    };
    notify.notified().await;

    // Delete auxinfo notification
    let mut state_notifications = state.auxinfo_notifications.write().await;
    state_notifications.remove(&auxinfo_identifier);
    drop(state_notifications);

    Ok(())
}

#[post("/keygen", data = "<parameters>")]
async fn keygen(
    state: &State<ParticipantState>,
    parameters: Json<KeygenParameters>,
) -> std::result::Result<Json<CurvePoint>, ErrorWrapper> {
    let _auxinfo_identifier = parameters.auxinfo_identifier;
    let keygen_identifier = parameters.keygen_identifier;

    let participant = {
        let state_participant = state.participant.read().await;
        (*state_participant)
            .clone()
            .ok_or_else(|| anyhow!("Config not set"))?
    };
    let message = participant.initialize_keygen_message(keygen_identifier);
    drop(participant);

    // Create new notification for this keygen identifier
    let mut state_notifications = state.keygen_notifications.write().await;
    state_notifications.insert(keygen_identifier, Arc::new(Notify::new()));
    drop(state_notifications);

    process(state, bincode::serialize(&message)?).await?;

    // Block until operation is done from process()
    let notify = {
        let notifications = state.keygen_notifications.read().await;
        notifications.get(&keygen_identifier).unwrap().clone()
    };
    notify.notified().await;

    // Delete keygen notification
    let mut state_notifications = state.keygen_notifications.write().await;
    state_notifications.remove(&keygen_identifier);
    drop(state_notifications);

    // Read from participant again to get the public keyshare
    let participant = {
        let state_participant = state.participant.read().await;
        (*state_participant)
            .clone()
            .ok_or_else(|| anyhow!("Config not set"))?
    };
    let curve_point = participant.get_public_keyshare(keygen_identifier)?;
    drop(participant);

    Ok(Json(curve_point))
}

#[post("/presign", data = "<parameters>")]
async fn presign(state: &State<ParticipantState>, parameters: Json<PresignParameters>) -> Result {
    let auxinfo_identifier = parameters.auxinfo_identifier;
    let keygen_identifier = parameters.keygen_identifier;
    let presign_identifier = parameters.presign_identifier;

    let mut state_participant = state.participant.write().await;
    let mut participant = (*state_participant)
        .clone()
        .ok_or_else(|| anyhow!("Config not set"))?;
    let message = participant.initialize_presign_message(
        auxinfo_identifier,
        keygen_identifier,
        presign_identifier,
    )?;

    *state_participant = Some(participant.clone());
    drop(state_participant); // Release the lock

    // Create new notification for this keygen identifier
    let mut state_notifications = state.presign_notifications.write().await;
    state_notifications.insert(presign_identifier, Arc::new(Notify::new()));
    drop(state_notifications);

    process(state, bincode::serialize(&message)?).await?;

    // Block until operation is done from process()
    let notify = {
        let notifications = state.presign_notifications.read().await;
        notifications.get(&presign_identifier).unwrap().clone()
    };
    notify.notified().await;

    // Delete presign notification
    let mut state_notifications = state.presign_notifications.write().await;
    state_notifications.remove(&presign_identifier);
    drop(state_notifications);

    Ok(())
}

/// Seems like k256::Scalar serialization/deserialization is broken, so we
/// cannot return a Json<Signature> here. Instead, we are going for the uglier
/// fix of returning two Vec<u8>s, one for r and one for s.
#[post("/sign_from_presign", data = "<parameters>")]
async fn sign_from_presign(
    state: &State<ParticipantState>,
    parameters: Json<SignFromPresignParameters>,
) -> std::result::Result<Json<(Vec<u8>, Vec<u8>)>, ErrorWrapper> {
    use sha2::{Digest, Sha256};

    let presign_identifier = parameters.presign_identifier;

    let mut hasher = Sha256::new();
    hasher.update(parameters.input.clone());

    let mut state_participant = state.participant.write().await;
    let mut participant = (*state_participant)
        .clone()
        .ok_or_else(|| anyhow!("Config not set"))?;

    let signature_share = participant.sign(presign_identifier, hasher.clone())?;

    *state_participant = Some(participant.clone());
    drop(state_participant); // Release the lock

    Ok(Json((
        signature_share.r.unwrap().to_bytes().to_vec(),
        signature_share.s.to_bytes().to_vec(),
    )))
}
