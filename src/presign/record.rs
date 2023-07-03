// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{
        InternalError::{InternalInvariantFailed, ProtocolError},
        Result,
    },
    presign::round_three::{Private as RoundThreePrivate, Public as RoundThreePublic},
    protocol::SignatureShare,
    utils::{bn_to_scalar, CurvePoint, ParseBytes},
};
use k256::{
    elliptic_curve::{AffineXCoordinate, PrimeField},
    Scalar,
};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use tracing::{error, info, instrument};
use zeroize::ZeroizeOnDrop;

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
#[derive(ZeroizeOnDrop, PartialEq, Eq)]
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
            Delta = CurvePoint(Delta.0 + p.Delta.0);
        }

        let g = CurvePoint::GENERATOR;
        if CurvePoint(g.0 * delta) != Delta {
            error!("Could not create PresignRecord: mismatch between calculated private and public deltas");
            return Err(ProtocolError);
        }

        let delta_inv = Option::<Scalar>::from(delta.invert()).ok_or_else(|| {
            error!("Could not invert delta as it is 0. Either you got profoundly unlucky or more likely there's a bug");
            InternalInvariantFailed
        })?;
        let R = CurvePoint(private.Gamma.0 * delta_inv);

        Ok(PresignRecord {
            R,
            k: bn_to_scalar(&private.k)?,
            chi: private.chi,
        })
    }
}

impl PresignRecord {
    /// Generate a signature share for the given [`Sha256`] instance.
    ///
    /// This method consumes the [`PresignRecord`] since it must only be used
    /// for a single signature.
    #[instrument(skip_all, err(Debug))]
    pub fn sign(self, hasher: Sha256) -> Result<SignatureShare> {
        info!("Issuing signature with presign record.");
        // Compute the x-projection of `R` (`r` in the paper).
        let x_projection = self.R.0.to_affine().x();
        let x_projection = Option::from(Scalar::from_repr(x_projection)).ok_or_else(|| {
            error!("Unable to compute x-projection of curve point: failed to convert projection to `Scalar`");
            InternalInvariantFailed
        })?;
        // Compute the digest (as a `Scalar`) of the message provided in
        // `hasher` (`m` in the paper).
        let digest =
            Option::<Scalar>::from(Scalar::from_repr(hasher.finalize())).ok_or_else(|| {
                error!(
                    "Unable to compute message digest: failed to convert bytestring to `Scalar`"
                );
                InternalInvariantFailed
            })?;
        // Produce a ECDSA signature share of the digest (`σ` in the paper).
        let signature_share = self.k * digest + x_projection * self.chi;
        Ok(SignatureShare::new(x_projection, signature_share))
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


        let mut = self.R.to_bytes();
        let share_len = share.len().to_le_bytes();

        let bytes = [RECORD_TAG, &share_len, &share].concat();
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
            todo!()
            /*

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
            let share_len_slice = parser.take_bytes(KEYSHARE_LEN)?;
            let share_len_bytes: [u8; KEYSHARE_LEN] = share_len_slice.try_into().map_err(|_| {
                error!(
                    "Failed to convert byte array (should always work because we
                defined it to be exactly 8 bytes"
                );
                InternalError::InternalInvariantFailed
            })?;
            let share_len = usize::from_le_bytes(share_len_bytes);

            let share_bytes = parser.take_rest()?;
            if share_bytes.len() != share_len {
                Err(CallerError::DeserializationFailed)?
            }

            // Check that the share itself is valid
            let share = BigNumber::from_slice(share_bytes);
            if share > k256_order() || share < BigNumber::one() {
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
 */
    }
}
