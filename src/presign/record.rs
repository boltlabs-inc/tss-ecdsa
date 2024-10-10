// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{
        CallerError,
        InternalError::{InternalInvariantFailed, ProtocolError},
        Result,
    },
    presign::round_three::{Private as RoundThreePrivate, Public as RoundThreePublic},
    utils::{bn_to_scalar, CurvePoint, ParseBytes},
};
use k256::{elliptic_curve::PrimeField, Scalar};
use std::fmt::Debug;
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) struct RecordPair {
    pub(crate) private: RoundThreePrivate,
    pub(crate) publics: Vec<RoundThreePublic>,
}

/// The precomputation used to create a partial signature.
///
/// # 🔒 Storage requirements
/// This type must be stored securely by the calling application.
///
/// # 🔒 Lifetime requirements
/// This type must only be used _once_.
///
/// # High-level protocol description
/// A `PresignRecord` contains the following components of the ECSDA signature
/// algorithm[^cite] (the below notation matches the notation used in the
/// citation):
/// - A curve point (`R` in the paper) representing the point `k^{-1} · G`,
///   where `k` is a random integer and `G` denotes the elliptic curve base
///   point.
/// - A [`Scalar`] (`kᵢ` in the paper) representing a share of the random
///   integer `k^{-1}`.
/// - A [`Scalar`] (`χᵢ` in the paper) representing a share of `k^{-1} · d_A`,
///   where `d_A` is the ECDSA secret key.
///
/// To produce a signature share of a message digest `m`, we simply compute `kᵢ
/// m + r χᵢ`, where `r` denotes the x-axis projection of `R`. Note that by
/// combining all of these shares, we get `(∑ kᵢ) m + r (∑ χᵢ) = k^{-1} (m + r
/// d_A)`, which is exactly a valid (normal) ECDSA signature.
///
/// [^cite]: [Wikipedia](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm)
#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct PresignRecord {
    R: CurvePoint,
    k: Scalar,
    chi: Scalar,
}

const RECORD_TAG: &[u8] = b"Presign Record";

impl Debug for PresignRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacting all the fields because I'm not sure how sensitive they are. If
        // later analysis suggests they're fine to print, please udpate
        // accordingly.
        f.debug_struct("PresignRecord")
            .field("R", &"[redacted]")
            .field("k", &"[redacted]")
            .field("chi", &"[redacted]")
            .finish()
    }
}

impl TryFrom<RecordPair> for PresignRecord {
    type Error = crate::errors::InternalError;
    fn try_from(RecordPair { private, publics }: RecordPair) -> Result<Self> {
        let mut delta = private.delta;
        let mut Delta = private.Delta;
        for p in publics {
            delta += &p.delta;
            Delta = Delta + p.Delta;
        }

        let g = CurvePoint::GENERATOR;
        if g.multiply_by_scalar(&delta) != Delta {
            error!("Could not create PresignRecord: mismatch between calculated private and public deltas");
            return Err(ProtocolError(None));
        }

        let delta_inv = Option::<Scalar>::from(delta.invert()).ok_or_else(|| {
            error!("Could not invert delta as it is 0. Either you got profoundly unlucky or more likely there's a bug");
            InternalInvariantFailed
        })?;
        let R = private.Gamma.multiply_by_scalar(&delta_inv);

        Ok(PresignRecord {
            R,
            k: bn_to_scalar(&private.k)?,
            chi: private.chi,
        })
    }
}

impl PresignRecord {
    /// Get the mask share (`k` in the paper) from the record.
    pub(crate) fn mask_share(&self) -> &Scalar {
        &self.k
    }

    /// Get the masked key share (`chi` in the paper) from the record.
    pub(crate) fn masked_key_share(&self) -> &Scalar {
        &self.chi
    }
    /// Compute the x-projection of the randomly-selected point `R` from the
    /// [`PresignRecord`].
    pub(crate) fn x_projection(&self) -> Result<Scalar> {
        let x_projection = self.R.x_affine();

        // Note: I don't think this is a foolproof transformation. The `from_repr`
        // method expects a scalar in the range `[0, q)`, but there's no
        // guarantee that the x-coordinate of `R` will be in that range.
        Option::from(Scalar::from_repr(x_projection)).ok_or_else(|| {
            error!("Unable to compute x-projection of curve point: failed to convert x coord to `Scalar`");
            InternalInvariantFailed
        })
    }

    /// Convert private material into bytes.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. The output of this function should be handled with care.
    pub fn into_bytes(self) -> Vec<u8> {
        // Format:
        // RECORD TAG
        // Curve point length in bytes (8 bytes)
        // Curve point
        // k randomness share length in bytes (8 bytes)
        // k randomness share
        // chi share length in bytes (8 bytes)
        // chi share

        let mut point = self.R.to_bytes();
        let point_len = point.len().to_le_bytes();

        let mut random_share = self.k.to_bytes();
        let random_share_len = random_share.len().to_le_bytes();

        let mut chi_share = self.chi.to_bytes();
        let chi_share_len = chi_share.len().to_le_bytes();

        let bytes = [
            RECORD_TAG,
            &point_len,
            &point,
            &random_share_len,
            random_share.as_ref(),
            &chi_share_len,
            chi_share.as_ref(),
        ]
        .concat();

        point.zeroize();
        random_share.zeroize();
        chi_share.zeroize();

        bytes
    }

    /// Convert bytes into private material.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. Do not use this method to create arbitrary instances of
    /// [`PresignRecord`].
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Expected format:
        // RECORD_TAG | key_len in bytes | key (big endian bytes)
        //              | 8 bytes          | key_len bytes

        let mut parser = ParseBytes::new(bytes);

        // This little function ensures that
        // 1. We can zeroize out the potentially-sensitive input bytes regardless of
        //    whether parsing succeeded; and
        // 2. We can log the error message once at the end, rather than duplicating it
        //    across all the parsing code
        let mut parse = || -> Result<PresignRecord> {
            // Make sure the RECORD_TAG is correct.
            let actual_tag = parser.take_bytes(RECORD_TAG.len())?;
            if actual_tag != RECORD_TAG {
                Err(CallerError::DeserializationFailed)?
            }

            // Parse the curve point
            let point_len = parser.take_len()?;
            let point_bytes = parser.take_bytes(point_len)?;
            let point = CurvePoint::try_from_bytes(point_bytes)?;

            // Parse the random share `k`
            let random_share_len = parser.take_len()?;
            let random_share_slice = parser.take_bytes(random_share_len)?;
            let mut random_share_bytes: [u8; 32] = random_share_slice
                .try_into()
                .map_err(|_| CallerError::DeserializationFailed)?;
            let random_share: Option<_> = Scalar::from_repr(random_share_bytes.into()).into();
            random_share_bytes.zeroize();

            // Parse the chi share
            let chi_share_len = parser.take_len()?;
            let chi_share_slice = parser.take_rest()?;
            if chi_share_slice.len() != chi_share_len {
                Err(CallerError::DeserializationFailed)?
            }
            let mut chi_share_bytes: [u8; 32] = chi_share_slice
                .try_into()
                .map_err(|_| CallerError::DeserializationFailed)?;
            let chi_share: Option<_> = Scalar::from_repr(chi_share_bytes.into()).into();
            chi_share_bytes.zeroize();

            // The random and chi shares both need to be elements of `F_q`;
            // the k256::Scalar's parsing methods check this for us.

            match (random_share, chi_share) {
                (Some(k), Some(chi)) => Ok(Self { R: point, k, chi }),
                _ => Err(CallerError::DeserializationFailed)?,
            }
        };

        let result = parse();

        // During parsing, we copy all the bytes we need into the appropriate types.
        // Here, we delete the original copy.
        parser.zeroize();

        // Log a message in case of error
        if result.is_err() {
            error!(
                "Failed to deserialize `PresignRecord`. Expected format:
                    {:?} | curve_point | k | chi
                where the last three elements are each prepended by an 8 byte
                little-endian encoded usize describing the length of the remainder of the field",
                RECORD_TAG
            );
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use k256::{elliptic_curve::Field, Scalar};
    use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};

    use crate::{
        keygen,
        presign::{participant::presign_record_set_is_valid, record::RECORD_TAG},
        utils::{bn_to_scalar, testing::init_testing, CurvePoint},
        ParticipantConfig, PresignRecord,
    };

    impl PresignRecord {
        pub(crate) fn mask_point(&self) -> &CurvePoint {
            &self.R
        }

        /// Simulate creation of a random presign record. Do not use outside of
        /// testing.
        pub(crate) fn simulate(rng: &mut StdRng) -> PresignRecord {
            let mask_point = CurvePoint::random(StdRng::from_seed(rng.gen()));
            let mask_share = Scalar::random(StdRng::from_seed(rng.gen()));
            let masked_key_share = Scalar::random(rng);

            PresignRecord {
                R: mask_point,
                k: mask_share,
                chi: masked_key_share,
            }
        }

        /// Simulate generation of a valid set of presign records to correspond
        /// with the provided keygen outputs.
        ///
        /// For testing only; this does not check that the keygen output set is
        /// consistent or complete.
        pub(crate) fn simulate_set(
            keygen_outputs: &[keygen::Output],
            rng: &mut (impl CryptoRng + RngCore),
        ) -> Vec<Self> {
            // Note: using slightly-biased generation for faster tests
            let mask_shares = std::iter::repeat_with(|| Scalar::generate_biased(rng))
                .take(keygen_outputs.len())
                .collect::<Vec<_>>();
            let mask = mask_shares
                .iter()
                .fold(Scalar::ZERO, |sum, mask_share| sum + mask_share);
            let mask_inversion = Option::<Scalar>::from(mask.invert()).unwrap();
            // `R` in the paper.
            let mask_point = CurvePoint::GENERATOR.multiply_by_scalar(&mask_inversion);

            // Compute the masked key shares as (secret_key_share * mask)
            let masked_key_shares = keygen_outputs
                .iter()
                .map(|output| bn_to_scalar(output.private_key_share().as_ref()).unwrap())
                .map(|secret_key_share| secret_key_share * mask);

            assert_eq!(masked_key_shares.len(), keygen_outputs.len());
            assert_eq!(mask_shares.len(), keygen_outputs.len());

            std::iter::zip(masked_key_shares, mask_shares)
                .map(|(masked_key_share, mask_share)| Self {
                    R: mask_point,
                    k: mask_share,
                    chi: masked_key_share,
                })
                .collect()
        }
    }

    #[test]
    fn simulated_presign_output_is_valid() {
        let rng = &mut init_testing();
        let configs = ParticipantConfig::random_quorum(5, rng).unwrap();
        let keygen_outputs = keygen::Output::simulate_set(&configs, rng);
        let records = PresignRecord::simulate_set(&keygen_outputs, rng);

        // Check validity of set; this will panic if anything is wrong
        presign_record_set_is_valid(records, keygen_outputs);
    }

    #[test]
    fn record_bytes_conversion_works() {
        let rng = &mut init_testing();
        let record = PresignRecord::simulate(rng);
        let clone = PresignRecord { ..record };

        let bytes = record.into_bytes();
        let reconstructed = PresignRecord::try_from_bytes(bytes);

        assert!(reconstructed.is_ok());
        assert_eq!(reconstructed.unwrap(), clone);
    }

    #[test]
    fn deserialized_record_tag_must_be_correct() {
        let rng = &mut init_testing();
        let record = PresignRecord::simulate(rng);

        // Cut out the tag from the serialized bytes for convenience.
        let share_bytes = &record.into_bytes()[RECORD_TAG.len()..];

        // Tag must have correct content
        let wrong_tag = b"NotTheRightTag";
        assert_eq!(wrong_tag.len(), RECORD_TAG.len());
        let bad_bytes = [wrong_tag.as_slice(), share_bytes].concat();
        assert!(PresignRecord::try_from_bytes(bad_bytes).is_err());

        // Tag must be correct length (too short, too long)
        let short_tag = &RECORD_TAG[..5];
        let bad_bytes = [short_tag, share_bytes].concat();
        assert!(PresignRecord::try_from_bytes(bad_bytes).is_err());

        let bad_bytes = [RECORD_TAG, b"TAG EXTENSION!", share_bytes].concat();
        assert!(PresignRecord::try_from_bytes(bad_bytes).is_err());

        // Normal serialization works
        let bytes = [RECORD_TAG, share_bytes].concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_ok());
    }

    fn test_length_field(front: &[u8], len: usize, back: &[u8]) {
        // Length must be specified
        let bad_bytes = [front, back].concat();
        assert!(PresignRecord::try_from_bytes(bad_bytes).is_err());

        // Length must be little endian
        let bad_bytes = [front, &len.to_be_bytes(), back].concat();
        assert!(PresignRecord::try_from_bytes(bad_bytes).is_err());

        // Length must be correct (too long, too short)
        let too_short = (len - 5).to_le_bytes();
        let bad_bytes = [front, &too_short, back].concat();
        assert!(PresignRecord::try_from_bytes(bad_bytes).is_err());

        let too_long = (len + 5).to_le_bytes();
        let bad_bytes = [front, &too_long, back].concat();
        assert!(PresignRecord::try_from_bytes(bad_bytes).is_err());

        // Correct length works
        let bytes = [front, &len.to_le_bytes(), back].concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_ok());
    }

    #[test]
    fn point_field_must_have_length_prepended() {
        let rng = &mut init_testing();
        let PresignRecord { R, k, chi } = PresignRecord::simulate(rng);

        let point = R.to_bytes();

        let random_share = k.to_bytes();
        let random_share_len = random_share.len().to_le_bytes();

        let chi_share = chi.to_bytes();
        let chi_share_len = chi_share.len().to_le_bytes();

        let back = [
            point.as_slice(),
            &random_share_len,
            random_share.as_ref(),
            &chi_share_len,
            chi_share.as_ref(),
        ]
        .concat();

        test_length_field(RECORD_TAG, point.len(), &back)
    }

    #[test]
    fn k_field_must_have_length_prepended() {
        let rng = &mut init_testing();
        let PresignRecord { R, k, chi } = PresignRecord::simulate(rng);

        let point = R.to_bytes();
        let point_len = point.len().to_le_bytes();

        let random_share = k.to_bytes();
        let front = [RECORD_TAG, &point_len, &point].concat();

        let chi_share = chi.to_bytes();
        let chi_share_len = chi_share.len().to_le_bytes();

        let back = [random_share.as_slice(), &chi_share_len, &chi_share].concat();

        test_length_field(&front, random_share.len(), &back)
    }

    #[test]
    fn chi_field_must_have_length_prepended() {
        let rng = &mut init_testing();
        let PresignRecord { R, k, chi } = PresignRecord::simulate(rng);

        let point = R.to_bytes();
        let point_len = point.len().to_le_bytes();

        let random_share = k.to_bytes();
        let random_share_len = random_share.len().to_le_bytes();

        let chi_share = chi.to_bytes();

        let front = [
            RECORD_TAG,
            &point_len,
            &point,
            &random_share_len,
            random_share.as_ref(),
        ]
        .concat();

        test_length_field(&front, chi_share.len(), chi_share.as_ref())
    }

    #[test]
    fn deserialized_keyshare_private_requires_all_fields() {
        let rng = &mut init_testing();

        // Part of a tag or the whole tag alone doesn't pass
        let bytes = &RECORD_TAG[..3];
        assert!(PresignRecord::try_from_bytes(bytes.to_vec()).is_err());
        assert!(PresignRecord::try_from_bytes(RECORD_TAG.to_vec()).is_err());

        let PresignRecord { R, k, chi } = PresignRecord::simulate(rng);

        let point = R.to_bytes();
        let point_len = point.len().to_le_bytes();

        let random_share = k.to_bytes();
        let random_share_len = random_share.len().to_le_bytes();

        let chi_share = chi.to_bytes();
        let chi_share_len = chi_share.len().to_le_bytes();

        let zero_len = 0usize.to_le_bytes();

        // Length with no curve point following doesn't pass
        let bytes = [RECORD_TAG, &point_len].concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_err());

        // Zero-length doesn't pass
        let bytes = [RECORD_TAG, &zero_len].concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_err());

        // Length with no randomness share following doesn't pass
        let bytes = [RECORD_TAG, &point_len, &point, &random_share_len].concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_err());

        let bytes = [RECORD_TAG, &point_len, &point, &zero_len].concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_err());

        // Length with no chi share following doesn't pass
        let bytes = [
            RECORD_TAG,
            &point_len,
            &point,
            &random_share_len,
            random_share.as_ref(),
            &chi_share_len,
        ]
        .concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_err());

        let bytes = [
            RECORD_TAG,
            &point_len,
            &point,
            &random_share_len,
            random_share.as_ref(),
            &zero_len,
        ]
        .concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_err());

        // Full thing works (e.g. the encoding scheme used above is correct)
        let bytes = [
            RECORD_TAG,
            &point_len,
            &point,
            &random_share_len,
            random_share.as_ref(),
            &chi_share_len,
            chi_share.as_ref(),
        ]
        .concat();
        assert!(PresignRecord::try_from_bytes(bytes).is_ok());
    }
}
