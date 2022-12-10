// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    client::{invoke_auxinfo, invoke_keygen, invoke_presign, invoke_sign_from_presign},
    common::Result,
};
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use std::collections::HashMap;
use tss_ecdsa::{Identifier, ParticipantIdentifier};

#[derive(Debug)]
enum CliType {
    AuxInfo,
    Keypair,
    Presignature,
    SignFromPresign,
    Quit,
}

struct CliOption {
    cli_type: CliType,
    text: String,
}

pub(crate) async fn render_cli(ports_to_ids: &HashMap<u16, ParticipantIdentifier>) -> Result {
    use dialoguer::{theme::ColorfulTheme, Input, Select};

    let mut auxinfos: Vec<Identifier> = vec![];
    let mut keypairs: Vec<Identifier> = vec![];
    let mut presignatures: Vec<Identifier> = vec![];

    let mut keygen_to_vk_map = HashMap::new();
    let mut presign_to_keygen_map = HashMap::new();

    let mut rng = OsRng;

    loop {
        let mut items: Vec<CliOption> = vec![CliOption {
            cli_type: CliType::AuxInfo,
            text: "Generate auxiliary info".to_string(),
        }];

        if !auxinfos.is_empty() {
            items.push(CliOption {
                cli_type: CliType::Keypair,
                text: "Generate keypair".to_string(),
            });
        }

        if !auxinfos.is_empty() && !keypairs.is_empty() {
            items.push(CliOption {
                cli_type: CliType::Presignature,
                text: "Generate presignature".to_string(),
            });
        }

        if !presignatures.is_empty() {
            items.push(CliOption {
                cli_type: CliType::SignFromPresign,
                text: "Generate signature from presignature".to_string(),
            });
        }

        items.push(CliOption {
            cli_type: CliType::Quit,
            text: "Quit".to_string(),
        });

        let selection = Select::with_theme(&ColorfulTheme::default())
            .items(
                &items
                    .iter()
                    .map(|item| item.text.clone())
                    .collect::<Vec<String>>(),
            )
            .default(0)
            .interact_opt()?;

        match selection {
            Some(index) => match items[index].cli_type {
                CliType::AuxInfo => {
                    let auxinfo_identifier = Identifier::random(&mut rng);
                    invoke_auxinfo(ports_to_ids, auxinfo_identifier).await?;
                    auxinfos.push(auxinfo_identifier);
                }
                CliType::Keypair => {
                    let auxinfo_selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("In order to generate a keypair, first select an auxinfo:")
                        .items(&auxinfos)
                        .default(0)
                        .interact()?;
                    let auxinfo_identifier = auxinfos[auxinfo_selection];

                    let keygen_identifier = Identifier::random(&mut rng);
                    invoke_keygen(
                        ports_to_ids,
                        &mut keygen_to_vk_map,
                        auxinfo_identifier,
                        keygen_identifier,
                    )
                    .await?;
                    keypairs.push(keygen_identifier);
                }
                CliType::Presignature => {
                    let auxinfo_selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt(
                            "In order to generate a presignature, first select an auxinfo:",
                        )
                        .items(&auxinfos)
                        .default(0)
                        .interact()?;
                    let auxinfo_identifier = auxinfos[auxinfo_selection];

                    let keypair_selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("Then, select a keypair:")
                        .items(&keypairs)
                        .default(0)
                        .interact()?;
                    let keygen_identifier = keypairs[keypair_selection];

                    let presign_identifier = Identifier::random(&mut rng);
                    invoke_presign(
                        ports_to_ids,
                        auxinfo_identifier,
                        keygen_identifier,
                        presign_identifier,
                    )
                    .await?;
                    presignatures.push(presign_identifier);
                    presign_to_keygen_map.insert(presign_identifier, keygen_identifier);
                }
                CliType::SignFromPresign => {
                    let presignature_selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("In order to sign from a presignature, select a presignature:")
                        .items(&presignatures)
                        .default(0)
                        .interact()?;
                    let presign_identifier = presignatures[presignature_selection];
                    let keygen_identifier = presign_to_keygen_map.get(&presign_identifier).unwrap();

                    let input: String = Input::new()
                        .with_prompt("Next, type in a message to be signed")
                        .interact_text()?;

                    invoke_sign_from_presign(
                        ports_to_ids,
                        presign_identifier,
                        input.as_bytes().to_vec(),
                        keygen_to_vk_map.get(keygen_identifier).unwrap(),
                    )
                    .await?;

                    // Delete the presignature, since it should not be used to sign again
                    presignatures.retain(|&x| x != presign_identifier);
                }
                CliType::Quit => {
                    break;
                }
            },
            None => {
                break;
            }
        }
    }

    Ok(())
}

pub(crate) fn start_progress_bar() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(80);
    pb.set_message("Waiting for servers to respond...");
    let waiting_style = ProgressStyle::default_spinner()
        .template("[{elapsed_precise}] {spinner:.cyan/blue} {msg:.yellow}")
        .tick_strings(&[
            "[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]", "[    ]",
            "[   =]", "[  ==]", "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]",
        ]);

    pb.set_style(waiting_style);
    pb
}

pub(crate) fn finish_progress_bar(pb: ProgressBar, message: String) {
    let done_style =
        ProgressStyle::default_spinner().template("[{elapsed_precise}] {msg:.bold.green}");
    pb.set_style(done_style);
    pb.finish_with_message(message);
}
