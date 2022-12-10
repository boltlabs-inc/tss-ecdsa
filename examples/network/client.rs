// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    cli::{finish_progress_bar, render_cli, start_progress_bar},
    common::{Args, ParticipantInitConfig, Result},
    server::{AuxInfoParameters, KeygenParameters, PresignParameters, SignFromPresignParameters},
};
use generic_array::GenericArray;
use k256::ecdsa::{signature::DigestVerifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::task::JoinHandle;
use tss_ecdsa::{CurvePoint, Identifier, ParticipantConfig, ParticipantIdentifier, SignatureShare};

pub(crate) async fn client_main(args: Args) -> Result {
    if args.server_ports.len() < 2 {
        panic!("Need to specify at least two server ports");
    }

    let mut rng = OsRng;

    let mut ports_to_ids = HashMap::new();
    let mut ids_to_ports = HashMap::new();
    for port in args.server_ports {
        let id = ParticipantIdentifier::random(&mut rng);
        ports_to_ids.insert(port, id);
        ids_to_ports.insert(id, port);
    }

    let client = reqwest::Client::new();

    for (port, id) in ports_to_ids.clone() {
        let other_ids = ports_to_ids
            .clone()
            .values()
            .filter(|&id2| id != *id2)
            .copied()
            .collect();

        let config = ParticipantConfig { id, other_ids };
        let init_config = ParticipantInitConfig {
            config,
            ports_to_ids: ports_to_ids.clone(),
            ids_to_ports: ids_to_ports.clone(),
        };
        let config_bytes = bincode::serialize(&init_config)?;

        let _res = client
            .post(format!("http://127.0.0.1:{}/initialize/", port))
            .body(config_bytes)
            .send()
            .await?;
    }

    render_cli(&ports_to_ids).await?;

    Ok(())
}

pub(crate) async fn invoke_auxinfo(
    ports_to_ids: &HashMap<u16, ParticipantIdentifier>,
    auxinfo_identifier: Identifier,
) -> Result {
    let mut tasks: Vec<JoinHandle<_>> = vec![];
    for (port, _) in ports_to_ids.clone() {
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let request = client
                .post(format!("http://127.0.0.1:{}/auxinfo/", port))
                .json(&AuxInfoParameters { auxinfo_identifier })
                .send();
            request.await
        }));
    }

    let pb = start_progress_bar();
    for task in tasks {
        let response = task.await??;
        if !response.status().is_success() {
            return Err(anyhow!("Error with auxinfo: {:?}", response).into());
        }
    }
    finish_progress_bar(
        pb,
        format!("Generated AuxInfo with identifier: {}", auxinfo_identifier),
    );

    Ok(())
}

pub(crate) async fn invoke_keygen(
    ports_to_ids: &HashMap<u16, ParticipantIdentifier>,
    keygen_to_vk_map: &mut HashMap<Identifier, VerifyingKey>,
    auxinfo_identifier: Identifier,
    keygen_identifier: Identifier,
) -> Result {
    let mut tasks: Vec<JoinHandle<_>> = vec![];
    for (port, _) in ports_to_ids.clone() {
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let request = client
                .post(format!("http://127.0.0.1:{}/keygen/", port))
                .json(&KeygenParameters {
                    auxinfo_identifier,
                    keygen_identifier,
                })
                .send();
            request.await
        }));
    }

    let mut vk_point = CurvePoint::IDENTITY;

    let pb = start_progress_bar();
    for task in tasks {
        let response = task.await??;
        if !response.status().is_success() {
            return Err(anyhow!("Error with keygen: {:?}", response).into());
        }
        let curve_point = response.json::<CurvePoint>().await?;

        // Accumulate curve points together to construct the verification key
        vk_point = CurvePoint(vk_point.0 + curve_point.0);
    }

    let verification_key = VerifyingKey::from_encoded_point(&vk_point.0.to_affine().into())?;
    keygen_to_vk_map.insert(keygen_identifier, verification_key);
    finish_progress_bar(
        pb,
        format!(
            "Generated keypair with identifier: {}, and public key:\n\t{}",
            keygen_identifier,
            hex::encode(verification_key.to_bytes())
        ),
    );

    Ok(())
}

pub(crate) async fn invoke_presign(
    ports_to_ids: &HashMap<u16, ParticipantIdentifier>,
    auxinfo_identifier: Identifier,
    keygen_identifier: Identifier,
    presign_identifier: Identifier,
) -> Result {
    let mut tasks: Vec<JoinHandle<_>> = vec![];
    for (port, _) in ports_to_ids.clone() {
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let request = client
                .post(format!("http://127.0.0.1:{}/presign/", port))
                .json(&PresignParameters {
                    auxinfo_identifier,
                    keygen_identifier,
                    presign_identifier,
                })
                .send();
            request.await
        }));
    }

    let pb = start_progress_bar();
    for task in tasks {
        let response = task.await??;
        if !response.status().is_success() {
            return Err(anyhow!("Error with presign: {:?}", response).into());
        }
    }
    finish_progress_bar(
        pb,
        format!(
            "Generated presignature with identifier: {}",
            presign_identifier
        ),
    );

    Ok(())
}

pub(crate) async fn invoke_sign_from_presign(
    ports_to_ids: &HashMap<u16, ParticipantIdentifier>,
    presign_identifier: Identifier,
    input: Vec<u8>,
    verification_key: &VerifyingKey,
) -> Result {
    let mut tasks: Vec<JoinHandle<_>> = vec![];
    for (port, _) in ports_to_ids.clone() {
        let input_clone = input.clone();
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let request = client
                .post(format!("http://127.0.0.1:{}/sign_from_presign/", port))
                .json(&SignFromPresignParameters {
                    presign_identifier,
                    input: input_clone,
                })
                .send();
            request.await
        }));
    }

    let pb = start_progress_bar();
    let mut aggregator = SignatureShare::default();
    for task in tasks {
        let response = task.await??;
        if !response.status().is_success() {
            return Err(anyhow!("Error with sign_from_presign: {:?}", response).into());
        }

        // This ugliness could be replaced by a SignatureShare json if
        // k256::Scalar deserialization worked properly...
        let (r_bytes, s_bytes): (Vec<u8>, Vec<u8>) = response.json().await?;
        let signature_share = SignatureShare {
            r: Some(
                <k256::Scalar as k256::elliptic_curve::PrimeField>::from_repr(
                    GenericArray::clone_from_slice(&r_bytes),
                )
                .unwrap(),
            ),
            s: <k256::Scalar as k256::elliptic_curve::PrimeField>::from_repr(
                GenericArray::clone_from_slice(&s_bytes),
            )
            .unwrap(),
        };

        aggregator = aggregator.chain(signature_share)?;
    }
    let signature = aggregator.finish()?;

    // Verify the signature
    let mut digest = Sha256::new();
    digest.update(&input);
    assert!(verification_key.verify_digest(digest, &signature).is_ok());

    finish_progress_bar(
        pb,
        format!("Generated signature:\n\t{}", hex::encode(signature)),
    );

    Ok(())
}
