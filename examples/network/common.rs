// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use rocket::{
    response::{self, Responder},
    Request,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tss_ecdsa::{ParticipantConfig, ParticipantIdentifier};

pub(crate) type Result<T = ()> = std::result::Result<T, ErrorWrapper>;

#[derive(Debug)]
pub(crate) struct ErrorWrapper(pub(crate) anyhow::Error);

impl<E> From<E> for ErrorWrapper
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        ErrorWrapper(error.into())
    }
}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for ErrorWrapper {
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'static> {
        response::Debug(self.0).respond_to(request)
    }
}

#[derive(clap::Parser)]
pub(crate) struct Args {
    #[clap(short, long, arg_enum)]
    pub(crate) role: RoleType,
    #[clap(short, long, default_value_t = 8000)]
    pub(crate) port: u16,
    #[clap(short, long)]
    pub(crate) server_ports: Vec<u16>,
}

#[derive(clap::ArgEnum, Clone)]
pub(crate) enum RoleType {
    Server,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ParticipantInitConfig {
    pub(crate) config: ParticipantConfig,
    pub(crate) ports_to_ids: HashMap<u16, ParticipantIdentifier>,
    pub(crate) ids_to_ports: HashMap<ParticipantIdentifier, u16>,
}
