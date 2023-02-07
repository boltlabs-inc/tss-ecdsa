// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::collections::HashMap;

use crate::{
    auxinfo::info::AuxInfoPublic,
    errors::{
        InternalError::{self, CouldNotConvertToScalar, RetryFailed},
        Result,
    },
    storage::{StorableType, Storage},
    Identifier, Message, ParticipantIdentifier,
};
use generic_array::GenericArray;
use k256::{
    elliptic_curve::{bigint::Encoding, group::ff::PrimeField, AffinePoint, Curve},
    Secp256k1,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) const CRYPTOGRAPHIC_RETRY_MAX: usize = 500usize;

/// Wrapper around k256::ProjectivePoint so that we can define our own
/// serialization/deserialization for it
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct CurvePoint(pub k256::ProjectivePoint);

impl CurvePoint {
    pub(crate) const GENERATOR: Self = CurvePoint(k256::ProjectivePoint::GENERATOR);
    /// The identity point, used to initialize the aggregation of a verification
    /// key
    pub const IDENTITY: Self = CurvePoint(k256::ProjectivePoint::IDENTITY);
}

impl From<k256::ProjectivePoint> for CurvePoint {
    fn from(p: k256::ProjectivePoint) -> Self {
        Self(p)
    }
}

impl Serialize for CurvePoint {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let afp = AffinePoint::<Secp256k1>::from(self.0);
        afp.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CurvePoint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = AffinePoint::<Secp256k1>::deserialize(deserializer)?;
        Ok(Self(p.into()))
    }
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
        return arg_err!("min needs to be less than max");
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
pub(crate) fn plusminus_bn_random_from_transcript(
    transcript: &mut Transcript,
    n: &BigNumber,
) -> BigNumber {
    let mut is_neg_byte = vec![0u8; 1];
    transcript.challenge_bytes(b"sampling negation bit", is_neg_byte.as_mut_slice());
    let is_neg: bool = is_neg_byte[0] & 1 == 1;

    // The sampling method samples from the open interval, so add 1 to sample from
    // the _closed_ interval we want here.
    let open_interval_max = n + 1;
    let b = positive_bn_random_from_transcript(transcript, &open_interval_max);
    match is_neg {
        true => -b,
        false => b,
    }
}

/// Derive a deterministic pseduorandom value in `[0, n)` from the
/// [`Transcript`].
pub(crate) fn positive_bn_random_from_transcript(
    transcript: &mut Transcript,
    n: &BigNumber,
) -> BigNumber {
    let len = n.to_bytes().len();
    let mut t = vec![0u8; len];
    // To avoid sample bias, we can't take `t mod n`, because that would bias
    // smaller numbers. Instead, we re-sample a new value (different because
    // there's a new label in the transcript).
    loop {
        transcript.challenge_bytes(b"sampling randomness", t.as_mut_slice());
        let b = BigNumber::from_slice(t.as_slice());
        if &b < n {
            return b;
        }
    }
}

/// Generate a random `BigNumber` that is in the multiplicative group of
/// integers modulo `n`.
///
/// Note: In this application, `n` is typically the product of two primes. If
/// the drawn element is not coprime with `n` and is not `0 mod n`, then the
/// caller has accidentally stumbled upon the factorization of `n`!
/// This is a security issue when `n` is someone else's Paillier modulus, but
/// the chance of this happening is basically 0 and we drop the element anyway.
pub(crate) fn random_bn_in_z_star<R: RngCore + CryptoRng>(
    rng: &mut R,
    n: &BigNumber,
) -> Result<BigNumber> {
    // Try up to `CRYPTOGRAPHIC_RETRY_MAX` times to draw a non-zero element. This
    // should virtually never error, though.
    std::iter::repeat_with(|| BigNumber::from_rng(n, rng))
        .take(CRYPTOGRAPHIC_RETRY_MAX)
        .find(|result| result != &BigNumber::zero() && result.gcd(n) == BigNumber::one())
        .ok_or(RetryFailed)
}

pub(crate) fn bn_to_scalar(x: &BigNumber) -> Result<k256::Scalar> {
    // Take (mod q)
    let order = k256_order();

    let x_modded = x % order;
    let bytes = x_modded.to_bytes();

    let mut slice = vec![0u8; 32 - bytes.len()];
    slice.extend_from_slice(&bytes);
    let mut ret: k256::Scalar = Option::from(k256::Scalar::from_repr(
        GenericArray::clone_from_slice(&slice),
    ))
    .ok_or(CouldNotConvertToScalar)?;

    // Make sure to negate the scalar if the original input was negative
    if x < &BigNumber::zero() {
        ret = ret.negate();
    }

    Ok(ret)
}

pub(crate) fn k256_order() -> BigNumber {
    // Set order = q
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    BigNumber::from_slice(order_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bn_in_range() {
        // Statistical tests -- should generate random numbers that are long enough

        let mut max_len = 0;
        let num_bytes = 100;

        let mut rng = get_test_rng();
        for _ in 0..1000 {
            let bn = random_plusminus_by_size(&mut rng, num_bytes * 8);
            let len = bn.to_bytes().len();
            if max_len < len {
                max_len = len;
            }
        }

        assert!(max_len > num_bytes - 2);
    }

    #[test]
    fn test_bn_to_scalar_neg() {
        let neg1 = BigNumber::zero() - BigNumber::one();

        let scalar = bn_to_scalar(&neg1).unwrap();
        assert_eq!(k256::Scalar::ZERO, scalar.add(&k256::Scalar::ONE));
    }
}

////////////////////////////////
// Protocol Utility Functions //
////////////////////////////////

/// Errors unless there is one storable_type for each other participant in the
/// quorum.
pub(crate) fn has_collected_all_of_others(
    other_ids: &[ParticipantIdentifier],
    storage: &Storage,
    storable_type: StorableType,
    identifier: Identifier,
) -> Result<bool> {
    let indices: Vec<(StorableType, Identifier, ParticipantIdentifier)> = other_ids
        .iter()
        .map(|participant_id| (storable_type, identifier, *participant_id))
        .collect();
    storage.contains_batch(&indices)
}

/// Aggregate the other participants' public keyshares from storage. But don't
/// remove them from storage.
///
/// This returns a HashMap with the key as the participant id and the value as
/// the KeygenPublic
pub(crate) fn get_other_participants_public_auxinfo(
    other_ids: &[ParticipantIdentifier],
    storage: &Storage,
    identifier: Identifier,
) -> Result<HashMap<ParticipantIdentifier, AuxInfoPublic>> {
    if !has_collected_all_of_others(other_ids, storage, StorableType::AuxInfoPublic, identifier)? {
        return Err(InternalError::StorageItemNotFound);
    }

    let mut hm = HashMap::new();
    for &other_participant_id in other_ids {
        let val = storage.retrieve(
            StorableType::AuxInfoPublic,
            identifier,
            other_participant_id,
        )?;
        let _ = hm.insert(other_participant_id, deserialize!(&val)?);
    }
    Ok(hm)
}

pub(crate) fn process_ready_message(
    self_id: ParticipantIdentifier,
    other_ids: &[ParticipantIdentifier],
    storage: &mut Storage,
    message: &Message,
    storable_type: StorableType,
) -> Result<(Vec<Message>, bool)> {
    storage.store(storable_type, message.id(), message.from(), &[])?;

    let mut messages = vec![];

    // If message is coming from self, then tell the other participants that we are
    // ready
    if message.from() == self_id {
        for &other_id in other_ids {
            messages.push(Message::new(
                message.message_type(),
                message.id(),
                self_id,
                other_id,
                &[],
            ));
        }
    }

    // Make sure that all parties are ready before proceeding
    let mut fetch = vec![];
    for &participant in other_ids {
        fetch.push((storable_type, message.id(), participant));
    }
    fetch.push((storable_type, message.id(), self_id));
    let is_ready = storage.contains_batch(&fetch)?;

    Ok((messages, is_ready))
}

////////////////////////////
// Test Utility Functions //
////////////////////////////
#[cfg(test)]
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
/// Returns an rng to be used for testing. This will print the rng seed
/// to stderr so that if a test fails, the failing seed can be recovered
/// and used for debugging.
#[cfg(test)]
pub(crate) fn get_test_rng() -> StdRng {
    let mut seeder = OsRng;
    let seed = seeder.gen();
    eprintln!("seed: {seed:?}");
    StdRng::from_seed(seed)
}
