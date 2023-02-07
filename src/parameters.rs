// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Security parameter definitions.
//!
//! This module defines security parameters that ensure the protocol satisfies
//! 80-bit statistical security and 112-bit computational security (the paper
//! claims 128-bit computational security, but NIST's Recommendation for Key
//! Management \[1\] advises that a 2048-bit Paillier modulus only provides 112
//! bits of computational security).
//!
//! Values are sourced from throughout the paper \[2\], especially Figure 1
//! (page 5) and Table 2 (page 69).
//!
//! ## References
//! 1. Recommendation for Key Management, Special Publication 800-57 Part 1 Rev.
//! 5, NIST, 05/2020.    Interpreted via [keylength.org](https://www.keylength.com/en/compare/).
//! 2. UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! Ran Canetti,    Rosario Gennaro, Steven Goldfeder, Nikolao Makriyannis, Udi
//! Peled. EPrint version, Oct 2021.    [PDF](https://eprint.iacr.org/2021/060.pdf)

/// Security parameter κ defines the message size of an elliptic curve group
/// element, and is also used to derive other parameter sizes.
const SECURITY_PARAM: usize = 256;

/// One of the ranges in proofs with a range check.
///
/// Specifically, it defines the range for the plaintext value of a Paillier
/// ciphertexts (in [Π-enc](crate::zkp::pienc), [Π-log*](crate::zkp::pilog)) or
/// of a group commitment (in [Π-aff-g](crate::zkp::piaffg)).
/// The range value is `+/- 2^ELL`.
pub(crate) const ELL: usize = SECURITY_PARAM;

/// Defines one of the ranges in proofs with a range check.
///
/// Specifically, it defines the range for the plaintext value of a Paillier
/// ciphertext in [Π-aff-g](crate::zkp::piaffg).
/// The range value is `+/- 2^ELL_PRIME`.
pub(crate) const ELL_PRIME: usize = 5 * SECURITY_PARAM;

/// The flex space of a range check.
///
/// When a prover has a secret input `x` in the range `+/- 2^l`, the verifier
/// can check that the masked proof response corresponding to `x` is in the
/// range `+/- 2^(l + EPSILON)`. The same `EPSILON` value is used for all ranges
/// -- those defined by both [`ELL`] and [`ELL_PRIME`].
///
/// It is part of the completeness bound in the range check proofs.
/// ([Π-enc](crate::zkp::pienc), [Π-log*](crate::zkp::pilog), and
/// [Π-aff-g](crate::zkp::piaffg)).
pub(crate) const EPSILON: usize = 2 * SECURITY_PARAM;

/// Bit size of the (safe) prime factors of a Paillier modulus.
///
/// The product of two 1024-bit primes will produce 2048-bit Pallier moduli.
pub(crate) const PRIME_BITS: usize = 1024;

/// Number of repetitions required for statistical security in proofs that allow
/// an adversary to guess a challenge value correctly with probability 1/2.
pub(crate) const SOUNDNESS_PARAMETER: usize = 80;
