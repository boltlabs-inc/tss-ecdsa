// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use libpaillier::unknown_order::BigNumber;
use openssl::{self, bn::BigNum, error::ErrorStack};
use std::{
    fs::OpenOptions,
    io::prelude::*,
    time::{Duration, Instant},
};

const PRIME_BITS: usize = 1024;

/// Used to pre-generate `PRIME_SIZE`-bit safe primes, so that they can
/// be stored in a text file to make testing this library faster.
///
/// This produces a raw list of quoted primes. To actually use them, you'll have
/// to manually edit the file to make it a module and make the list a proper
/// type.
fn main() {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(format!("safe_primes_{PRIME_BITS}.txt"))
        .unwrap();

    let iterations = 1000;
    let mut failures = 0;

    // Set up timing
    let mut prev = Instant::now();
    let mut total_seconds = Duration::new(0, 0);

    println!("Generating {iterations} {PRIME_BITS}-bit safe primes...");
    for i in 0..iterations {
        // Generate a safe prime
        let prime_result = ossl_safe_prime();

        // Record time taken to generate
        let next = Instant::now();
        let duration = next - prev;
        prev = next;
        total_seconds += duration;

        // Make sure it worked x2
        let encoded_prime = match prime_result {
            Ok(prime) => prime,
            Err(e) => {
                println!("error generating prime: {e}");
                failures += 1;
                continue;
            }
        };

        match check_prime(encoded_prime) {
            Some(prime_hex) => {
                writeln!(file, "\"{prime_hex}\",").unwrap();
                file.flush().unwrap();
            }
            None => {
                println!("prime generation failed!");
                failures += 1;
            }
        }

        // Log progress
        if (i + 1) % 50 == 0 {
            println!(
                "Generated {} / {} in {} seconds",
                i + 1,
                iterations,
                total_seconds.as_secs()
            );
        }
    }
    println!(
        "Total average prime generation time: {} seconds",
        total_seconds.as_secs() as f64 / (iterations as f64 + 1.0)
    );
    println!("Failures: {failures} / {iterations}");
}

/// Use the default BigNumber crate to generate a safe prime and encode as a hex
/// string. At time of writing, this was Rust's `BigInt` library.
#[allow(unused)]
fn bignumber_safe_prime() -> String {
    let prime = BigNumber::safe_prime(PRIME_BITS);
    hex::encode(prime.to_bytes())
}

/// Use the openssl crate to generate a safe prime and encode.
/// This is way faster than Rust's `BigInt` library.
fn ossl_safe_prime() -> Result<String, ErrorStack> {
    let mut prime = BigNum::new()?;
    prime.generate_prime(PRIME_BITS as i32, true, None, None)?;
    Ok(prime.to_hex_str()?.to_string())
}

/// Make sure the generated prime is
/// (a) valid hex
/// (b) of the correct size, and
/// (c) a safe prime.
fn check_prime(prime_hex: String) -> Option<String> {
    let bn_prime = BigNumber::from_slice(hex::decode(&prime_hex).ok()?);

    // check size
    if bn_prime.bit_length() != PRIME_BITS {
        return None;
    }

    // check safe-primality
    if !bn_prime.is_prime() {
        return None;
    }
    let safe: BigNumber = (bn_prime - 1) / 2;
    if !safe.is_prime() {
        return None;
    }

    Some(prime_hex)
}
