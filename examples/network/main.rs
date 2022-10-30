// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! To run this, spin up at least two servers (three in this example)
//! on different ports and in separate terminals:
//! `cargo run --example network -- -r server -p 8000`
//! `cargo run --example network -- -r server -p 8001`
//! `cargo run --example network -- -r server -p 8002`
//!
//! Then, spin up a client which connects to each of the servers:
//! `cargo run --example network -- -r client -s 8000 -s 8001 -s 8002`

#[macro_use]
extern crate rocket;

#[macro_use]
extern crate anyhow;

mod cli;
mod client;
mod common;
mod server;

use clap::Parser;
use client::client_main;
use common::{Args, Result, RoleType};
use server::server_main;

#[rocket::main]
async fn main() -> Result {
    let args = Args::parse();

    match args.role {
        RoleType::Server => {
            server_main(args).await?;
        }
        RoleType::Client => {
            client_main(args).await?;
        }
    }

    Ok(())
}
