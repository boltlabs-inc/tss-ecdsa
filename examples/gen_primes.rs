// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use libpaillier::unknown_order::BigNumber;

use std::{
    fs::OpenOptions,
    io::prelude::*,
    time::{Duration, Instant},
};

/// Used to pre-generate 512-bit safe primes, so that they can
/// be stored in a text file to make testing this library faster

fn main() {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open("safe_primes_512.txt")
        .unwrap();

    let mut prev = Instant::now();

    let iterations = 1000;

    let mut total_seconds = Duration::new(0, 0);

    println!("Generating {} 512-bit safe primes...", iterations);
    for i in 0..iterations {
        let prime = BigNumber::safe_prime(512);
        let next = Instant::now();
        let duration = next - prev;
        prev = next;
        total_seconds += duration;
        println!("Generating that prime took: {} seconds", duration.as_secs());
        println!(
            "Total average prime generation time: {} seconds",
            total_seconds.as_secs() as f64 / (i as f64 + 1.0)
        );
        writeln!(file, "\"{}\",", hex::encode(prime.to_bytes())).unwrap();
        file.flush().unwrap();
    }
}
