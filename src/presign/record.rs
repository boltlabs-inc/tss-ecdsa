// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{
        InternalError::{CouldNotConvertToScalar, CouldNotInvertScalar, InternalInvariantFailed},
        Result,
    },
    utils::bn_to_scalar,
    CurvePoint,
};
use k256::Scalar;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::round_three::{Private as RoundThreePrivate, Public as RoundThreePublic};
use k256::elliptic_curve::{AffineXCoordinate, PrimeField};

pub(crate) struct RecordPair {
    pub(crate) private: RoundThreePrivate,
    pub(crate) publics: Vec<RoundThreePublic>,
}

/// The precomputation used to create a partial signature
#[derive(Serialize, Deserialize)]
pub(crate) struct PresignRecord {
    R: CurvePoint,
    k: BigNumber,
    chi: k256::Scalar,
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
            return Err(InternalInvariantFailed);
        }

        let delta_inv = Option::<Scalar>::from(delta.invert()).ok_or(CouldNotInvertScalar)?;
        let R = CurvePoint(private.Gamma.0 * delta_inv);

        Ok(PresignRecord {
            R,
            k: private.k,
            chi: private.chi,
        })
    }
}

impl PresignRecord {
    fn x_from_point(p: &CurvePoint) -> Result<k256::Scalar> {
        let r = &p.0.to_affine().x();
        Option::from(k256::Scalar::from_repr(*r)).ok_or(CouldNotConvertToScalar)
    }

    pub(crate) fn sign(&self, d: sha2::Sha256) -> Result<(k256::Scalar, k256::Scalar)> {
        let r = Self::x_from_point(&self.R)?;
        let m = Option::<Scalar>::from(k256::Scalar::from_repr(d.finalize()))
            .ok_or(CouldNotConvertToScalar)?;
        let s = bn_to_scalar(&self.k)? * m + r * self.chi;

        Ok((r, s))
    }
}
