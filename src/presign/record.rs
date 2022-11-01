// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{utils::bn_to_scalar, CurvePoint};
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

impl From<RecordPair> for PresignRecord {
    fn from(RecordPair { private, publics }: RecordPair) -> Self {
        let mut delta = private.delta;
        let mut Delta = private.Delta;
        for p in publics {
            delta += &p.delta;
            Delta = CurvePoint(Delta.0 + p.Delta.0);
        }

        let g = CurvePoint::GENERATOR;
        if CurvePoint(g.0 * delta) != Delta {
            // Error, failed to validate
            panic!("Error, failed to validate");
        }

        let R = CurvePoint(private.Gamma.0 * delta.invert().unwrap());

        PresignRecord {
            R,
            k: private.k,
            chi: private.chi,
        }
    }
}

impl PresignRecord {
    fn x_from_point(p: &CurvePoint) -> k256::Scalar {
        let r = &p.0.to_affine().x();
        k256::Scalar::from_repr(*r).unwrap()
    }

    pub(crate) fn sign(&self, d: sha2::Sha256) -> (k256::Scalar, k256::Scalar) {
        let r = Self::x_from_point(&self.R);
        let m = k256::Scalar::from_repr(d.finalize()).unwrap();
        let s = bn_to_scalar(&self.k).unwrap() * m + r * self.chi;

        (r, s)
    }
}
