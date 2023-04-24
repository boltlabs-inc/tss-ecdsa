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
    utils::bn_to_scalar,
    CurvePoint,
};
use k256::{
    elliptic_curve::{AffineXCoordinate, PrimeField},
    Scalar,
};
use libpaillier::unknown_order::BigNumber;
use sha2::Digest;
use std::fmt::Debug;
use tracing::error;
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
#[derive(ZeroizeOnDrop)]
pub struct PresignRecord {
    R: CurvePoint,
    k: BigNumber,
    chi: k256::Scalar,
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
            k: private.k.clone(),
            chi: private.chi,
        })
    }
}

impl PresignRecord {
    fn x_from_point(p: &CurvePoint) -> Result<k256::Scalar> {
        let r = &p.0.to_affine().x();
        Option::from(k256::Scalar::from_repr(*r)).ok_or_else(|| {
            error!("Unable to create Scalar from bytes representation");
            InternalInvariantFailed
        })
    }

    pub(crate) fn sign(&self, d: sha2::Sha256) -> Result<(k256::Scalar, k256::Scalar)> {
        let r = Self::x_from_point(&self.R)?;
        let m = Option::<Scalar>::from(k256::Scalar::from_repr(d.finalize())).ok_or_else(|| {
            error!("Unable to create Scalar from bytes representation");
            InternalInvariantFailed
        })?;
        let s = bn_to_scalar(&self.k)? * m + r * self.chi;

        Ok((r, s))
    }
}
