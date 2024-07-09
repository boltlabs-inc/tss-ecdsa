// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::curve_point::k256_order;
use crate::errors::{CallerError, InternalError, Result};
use generic_array::GenericArray;
use k256::{
    elliptic_curve::{
        bigint::Encoding,
        group::{ff::PrimeField, GroupEncoding},
        point::AffineCoordinates,
        AffinePoint, Curve,
    },
    EncodedPoint, FieldBytes, Scalar, Secp256k1,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;
use tracing::error;
use zeroize::Zeroize;

pub(crate) const CRYPTOGRAPHIC_RETRY_MAX: usize = 500usize;


/// Helper type for parsing byte array into slices.
///
/// This type implements [`Zeroize`]. When parsing secret types, you should
/// manually call `zeroize()` after parsing is complete.
#[derive(Zeroize)]
pub(crate) struct ParseBytes {
    bytes: Vec<u8>,
    offset: usize,
}

impl ParseBytes {
    /// Consume bytes for parsing.
    pub(crate) fn new(bytes: Vec<u8>) -> ParseBytes {
        ParseBytes { bytes, offset: 0 }
    }

    /// Take next `n` bytes from array.
    pub(crate) fn take_bytes(&mut self, n: usize) -> Result<&[u8]> {
        let slice = &self
            .bytes
            .get(self.offset..self.offset + n)
            .ok_or(CallerError::DeserializationFailed)?;
        self.offset += n;
        Ok(slice)
    }

    /// Parse the next 8 bytes as a little-endian encoded usize.
    pub(crate) fn take_len(&mut self) -> Result<usize> {
        const LENGTH_BYTES: usize = 8;

        let len_slice = self.take_bytes(LENGTH_BYTES)?;
        let len_bytes: [u8; LENGTH_BYTES] = len_slice.try_into().map_err(|_| {
            error!(
                "Failed to convert byte array (should always work because we
                   defined it to be exactly 8 bytes"
            );
            InternalError::InternalInvariantFailed
        })?;
        Ok(usize::from_le_bytes(len_bytes))
    }

    /// Take the rest of the bytes from the array.
    pub(crate) fn take_rest(&mut self) -> Result<&[u8]> {
        self.bytes
            .get(self.offset..)
            .ok_or(CallerError::DeserializationFailed.into())
    }
}

/// Returns `true` if `value ∊ [-2^n, 2^n]`.
pub(crate) fn within_bound_by_size(value: &BigNumber, n: usize) -> bool {
    let bound = BigNumber::one() << n;
    value <= &bound && value >= &-bound
}

/// Compute a^e (mod n).
#[cfg_attr(feature = "flame_it", flame("utils"))]
pub(crate) fn modpow(a: &BigNumber, e: &BigNumber, n: &BigNumber) -> BigNumber {
    a.modpow(e, n)
}

/// Sample a number uniformly at random from the range [0, n). This can be used
/// for sampling from a prime field `F_p` or the integers modulo `n` (for any
/// `n`).
pub(crate) fn random_positive_bn<R: RngCore + CryptoRng>(rng: &mut R, n: &BigNumber) -> BigNumber {
    BigNumber::from_rng(n, rng)
}

/// Sample a number uniformly at random from the range [-n, n].
pub(crate) fn random_plusminus<R: RngCore + CryptoRng>(rng: &mut R, n: &BigNumber) -> BigNumber {
    // `from_rng()` samples the _open_ interval, so add 1 to get the closed interval
    // for `n`
    let open_interval_max: BigNumber = n + 1;
    let val = BigNumber::from_rng(&open_interval_max, rng);
    let is_positive: bool = rng.gen();
    match is_positive {
        true => val,
        false => -val,
    }
}

/// Sample a number uniformly at random from the range `[-2^n, 2^n]`.
pub(crate) fn random_plusminus_by_size<R: RngCore + CryptoRng>(rng: &mut R, n: usize) -> BigNumber {
    let range = BigNumber::one() << n;
    random_plusminus(rng, &range)
}

/// Sample a number uniformly at random from the range `[-scale * 2^n, scale *
/// 2^n]`.
pub(crate) fn random_plusminus_scaled<R: RngCore + CryptoRng>(
    rng: &mut R,
    n: usize,
    scale: &BigNumber,
) -> BigNumber {
    let range = (BigNumber::one() << n) * scale;
    random_plusminus(rng, &range)
}

/// Sample a number uniformly at random from the range `[-2^max, -2^min] U
/// [2^min, 2^max]`.
#[cfg(test)]
pub(crate) fn random_plusminus_by_size_with_minimum<R: RngCore + CryptoRng>(
    rng: &mut R,
    max: usize,
    min: usize,
) -> crate::errors::Result<BigNumber> {
    if min >= max {
        tracing::error!(
            "Can't sample from specified range because lower bound is not smaller
             than upper bound. \nLower bound: {}\nUpper bound: {}",
            min,
            max
        );
        return Err(InternalError::InternalInvariantFailed);
    }
    // Sample from [0, 2^max - 2^min], then add 2^min to bump into correct range.
    let min_bound_bn = (BigNumber::one() << max) - (BigNumber::one() << min);
    let val = BigNumber::from_rng(&min_bound_bn, rng) + (BigNumber::one() << min);

    let is_positive: bool = rng.gen();
    Ok(match is_positive {
        true => val,
        false => -val,
    })
}

/// Derive a deterministic pseudorandom value in `[-n, n]` from the
/// [`Transcript`].
pub(crate) fn plusminus_challenge_from_transcript(
    transcript: &mut Transcript,
) -> Result<BigNumber> {
    let mut is_neg_byte = vec![0u8; 1];
    transcript.challenge_bytes(b"sampling negation bit", is_neg_byte.as_mut_slice());
    let is_neg: bool = is_neg_byte[0] & 1 == 1;

    // The sampling method samples from the open interval, so add 1 to sample from
    // the _closed_ interval we want here.
    let q = k256_order();
    let open_interval_max = &q + 1;
    let b = positive_challenge_from_transcript(transcript, &open_interval_max)?;
    Ok(match is_neg {
        true => -b,
        false => b,
    })
}

/// Derive a deterministic pseudorandom value in `[0, n)` from the
/// [`Transcript`].
pub(crate) fn positive_challenge_from_transcript(
    transcript: &mut Transcript,
    n: &BigNumber,
) -> Result<BigNumber> {
    // To avoid sample bias, we can't take `t mod n`, because that would bias
    // smaller numbers. Instead, we re-sample a new value (different because
    // there's a new label in the transcript).
    let len = n.to_bytes().len();
    let mut t = vec![0u8; len];
    for _ in 0..CRYPTOGRAPHIC_RETRY_MAX {
        transcript.challenge_bytes(b"sampling randomness", t.as_mut_slice());
        let b = BigNumber::from_slice(t.as_slice());
        if &b < n {
            return Ok(b);
        }
    }
    Err(CallerError::RetryFailed)?
}
