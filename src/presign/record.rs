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
    utils::{bn_to_scalar, CurvePoint},
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
#[derive(ZeroizeOnDrop)]
pub struct PresignRecord {
    R: CurvePoint,
    k: Scalar,
    chi: Scalar,
}

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
}
