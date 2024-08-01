// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{CallerError, Result},
    utils::{k256_order, CurvePoint, ParseBytes},
    ParticipantIdentifier,
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;
use zeroize::Zeroize;

const KEYSHARE_TAG: &[u8] = b"KeySharePrivate";

/// Private key corresponding to a given [`Participant`](crate::Participant)'s
/// [`KeySharePublic`].
///
/// # 🔒 Storage requirements
/// This type must be stored securely by the calling application.
#[derive(Clone, PartialEq, Eq)]
pub struct KeySharePrivate {
    x: BigNumber, // in the range [1, q)
}

impl Debug for KeySharePrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySharePrivate([redacted])")
    }
}

impl KeySharePrivate {
    /// Sample a private key share uniformly at random.
    pub fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let random_bn = BigNumber::from_rng(&k256_order(), rng);
        KeySharePrivate { x: random_bn }
    }

    /// Take a [`BigNumber`] as [`KeySharePrivate`]. `x_int` will be reduced
    /// modulo `q`.
    pub(crate) fn from_bigint(x_int: &BigNumber) -> Self {
        let x = x_int.nmod(&k256_order());
        Self { x }
    }

    /// Computes the "raw" curve point corresponding to this private key.
    pub(crate) fn public_share(&self) -> Result<CurvePoint> {
        CurvePoint::GENERATOR.multiply_by_bignum(&self.x)
    }

    /// Convert private material into bytes.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. The output of this function should be handled with care.
    pub fn into_bytes(self) -> Vec<u8> {
        // Format:
        // KEYSHARE_TAG | key_len in bytes | key (big endian bytes)
        //              | 8 bytes          | key_len bytes

        let mut share = self.x.to_bytes();
        let share_len = share.len().to_le_bytes();

        let bytes = [KEYSHARE_TAG, &share_len, &share].concat();
        share.zeroize();
        bytes
    }

    /// Convert bytes into private material.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. Do not use this method to create arbitrary instances of
    /// [`KeySharePrivate`].
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Expected format:
        // KEYSHARE_TAG | key_len in bytes | key (big endian bytes)
        //              | 8 bytes          | key_len bytes

        let mut parser = ParseBytes::new(bytes);

        // This little function ensures that
        // 1. We can zeroize out the potentially-sensitive input bytes regardless of
        //    whether parsing succeeded; and
        // 2. We can log the error message once at the end, rather than duplicating it
        //    across all the parsing code
        let mut parse = || {
            // Make sure the KEYSHARE_TAG is correct.
            let actual_tag = parser.take_bytes(KEYSHARE_TAG.len())?;
            if actual_tag != KEYSHARE_TAG {
                Err(CallerError::DeserializationFailed)?
            }

            // Extract the length of the key share
            let share_len = parser.take_len()?;

            let share_bytes = parser.take_rest()?;
            if share_bytes.len() != share_len {
                Err(CallerError::DeserializationFailed)?
            }

            // Check that the share itself is valid
            let share = BigNumber::from_slice(share_bytes);
            if share >= k256_order() || share < BigNumber::one() {
                Err(CallerError::DeserializationFailed)?
            }

            Ok(Self { x: share })
        };

        let result = parse();

        // During parsing, we copy all the bytes we need into the appropriate types.
        // Here, we delete the original copy.
        parser.zeroize();

        // Log a message in case of error
        if result.is_err() {
            error!(
                "Failed to deserialize `KeySharePrivate. Expected format:
                        {:?} | share_len | share
                        where `share_len` is a little-endian encoded usize
                        and `share` is exactly `share_len` bytes long.",
                KEYSHARE_TAG
            );
        }
        result
    }
}

impl AsRef<BigNumber> for KeySharePrivate {
    /// Get the private key share.
    fn as_ref(&self) -> &BigNumber {
        &self.x
    }
}

/// A curve point representing a given [`Participant`](crate::Participant)'s
/// public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySharePublic {
    participant: ParticipantIdentifier,
    X: CurvePoint,
}

impl KeySharePublic {
    pub(crate) fn new(participant: ParticipantIdentifier, share: CurvePoint) -> Self {
        Self {
            participant,
            X: share,
        }
    }

    /// Get the ID of the participant who claims to hold the private share
    /// corresponding to this public key share.
    pub fn participant(&self) -> ParticipantIdentifier {
        self.participant
    }

    /// Generate a new [`KeySharePrivate`] and [`KeySharePublic`].
    pub(crate) fn new_keyshare<R: RngCore + CryptoRng>(
        participant: ParticipantIdentifier,
        rng: &mut R,
    ) -> Result<(KeySharePrivate, KeySharePublic)> {
        let private_share = KeySharePrivate::random(rng);
        let public_share = private_share.public_share()?;

        Ok((
            private_share,
            KeySharePublic::new(participant, public_share),
        ))
    }
}

impl AsRef<CurvePoint> for KeySharePublic {
    /// Get the public curvepoint which is the public key share.
    fn as_ref(&self) -> &CurvePoint {
        &self.X
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        keygen::{keyshare::KEYSHARE_TAG, KeySharePrivate},
        utils::{k256_order, testing::init_testing},
    };

    #[test]
    fn keyshare_private_bytes_conversion_works() {
        let rng = &mut init_testing();
        let share = KeySharePrivate::random(rng);

        let bytes = share.clone().into_bytes();
        let reconstructed = KeySharePrivate::try_from_bytes(bytes);

        assert!(reconstructed.is_ok());
        assert_eq!(reconstructed.unwrap(), share);
    }

    #[test]
    fn keyshare_private_bytes_must_be_in_range() {
        // Share must be < k256_order()
        let too_big = KeySharePrivate { x: k256_order() };
        let bytes = too_big.into_bytes();
        assert!(KeySharePrivate::try_from_bytes(bytes).is_err());

        // Note: I tried testing the negative case but it seems like the
        // unknown_order crate's `from_bytes` method always interprets
        // numbers as positive. Unfortunately the crate does not
        // document the expected representation only noting that it
        // takes a big-endian byte sequence.
    }

    #[test]
    fn deserialized_keyshare_private_tag_must_be_correct() {
        let rng = &mut init_testing();
        let key_share = KeySharePrivate::random(rng);

        // Cut out the tag from the serialized bytes for convenience.
        let share_bytes = &key_share.into_bytes()[KEYSHARE_TAG.len()..];

        // Tag must have correct content
        let wrong_tag = b"NotTheRightTag!";
        assert_eq!(wrong_tag.len(), KEYSHARE_TAG.len());
        let bad_bytes = [wrong_tag.as_slice(), share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bad_bytes).is_err());

        // Tag must be correct length (too short, too long)
        let short_tag = &KEYSHARE_TAG[..5];
        let bad_bytes = [short_tag, share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bad_bytes).is_err());

        let bad_bytes = [KEYSHARE_TAG, b"TAG EXTENSION!", share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bad_bytes).is_err());

        // Normal serialization works
        let bytes = [KEYSHARE_TAG, share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bytes).is_ok());
    }

    #[test]
    fn deserialized_keyshare_private_length_field_must_be_correct() {
        let rng = &mut init_testing();
        let share_bytes = KeySharePrivate::random(rng).x.to_bytes();

        // Length must be specified
        let bad_bytes = [KEYSHARE_TAG, &share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bad_bytes).is_err());

        // Length must be little endian
        let share_len = share_bytes.len().to_be_bytes();
        let bad_bytes = [KEYSHARE_TAG, &share_len, &share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bad_bytes).is_err());

        // Length must be correct (too long, too short)
        let too_short = (share_bytes.len() - 5).to_le_bytes();
        let bad_bytes = [KEYSHARE_TAG, &too_short, &share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bad_bytes).is_err());

        let too_long = (share_bytes.len() + 5).to_le_bytes();
        let bad_bytes = [KEYSHARE_TAG, &too_long, &share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bad_bytes).is_err());

        // Correct length works
        let share_len = share_bytes.len().to_le_bytes();
        let bytes = [KEYSHARE_TAG, &share_len, &share_bytes].concat();
        assert!(KeySharePrivate::try_from_bytes(bytes).is_ok());
    }

    #[test]
    fn deserialized_keyshare_private_requires_all_fields() {
        // Part of a tag or the whole tag alone doesn't pass
        let bytes = &KEYSHARE_TAG[..3];
        assert!(KeySharePrivate::try_from_bytes(bytes.to_vec()).is_err());
        assert!(KeySharePrivate::try_from_bytes(KEYSHARE_TAG.to_vec()).is_err());

        // Length with no secret following doesn't pass
        let share_len = k256_order().bit_length() / 8;
        let bytes = [KEYSHARE_TAG, &share_len.to_le_bytes()].concat();
        assert!(KeySharePrivate::try_from_bytes(bytes).is_err());

        // Zero-length doesn't pass
        let bytes = [KEYSHARE_TAG, &0usize.to_le_bytes()].concat();
        assert!(KeySharePrivate::try_from_bytes(bytes).is_err());
    }

    use crate::enable_zeroize;
    use gmp_mpfr_sys::gmp;
    use libpaillier::unknown_order;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        mem::{align_of, size_of},
        slice,
    };

    #[allow(warnings)]
    #[test]
    fn zeroize_works() {
        // Set up automatic zeroization of GMP memory.
        enable_zeroize();

        // Generate a secret.
        let rng = &mut StdRng::from_seed([0; 32]);
        let mut share = KeySharePrivate::random(rng);

        // Pre-hack validation.
        assert!(
            size_of::<unknown_order::BigNumber>() == size_of::<gmp::mpz_t>() &&
            align_of::<unknown_order::BigNumber>() == align_of::<gmp::mpz_t>(),
            "unknown_order::BigNumber and rug::Integer should be a transparent wrapper of gmp::mpz_t."
        );

        // Dig down the stack of wrappers to get to the actual storage.
        let limb_size = size_of::<gmp::limb_t>();
        let data = unsafe {
            let mpz = &*(&share.x as *const unknown_order::BigNumber as *const gmp::mpz_t);
            slice::from_raw_parts(mpz.d.as_ptr() as *const u8, limb_size * mpz.size as usize)
        };

        // Post-hack validation.
        let expected_data = {
            let mut x = share.x.to_bytes();
            x.reverse(); // To little-endian.
            x.resize(x.len().div_ceil(limb_size) * limb_size, 0); // To complete limbs.
            x
        };
        assert_eq!(
            data,
            &expected_data[..],
            "Failed to locate the secret data."
        );

        // Prepare memory snapshots.
        let snapshot1 = &Vec::from(data) as &[u8];
        let snapshot2 = &mut Vec::from(data) as &mut [u8];

        // Dropping the secret should zeroize the underlying memory.
        drop(share);
        // Snapshot the memory again.
        snapshot2.copy_from_slice(&data);

        let unchanged_bytes_count = snapshot1
            .iter()
            .zip(snapshot2.iter())
            .filter(|(a, b)| a == b)
            .count();

        assert!(
            unchanged_bytes_count <= 4, // A few bytes can be equal by chance.
            "The secret should have been erased."
        );
    }
}
