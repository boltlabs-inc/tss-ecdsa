//! Elliptic Curve abstraction

use k256::{elliptic_curve::PrimeField, EncodedPoint, ProjectivePoint, Scalar};
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, ops::Add};
use tracing::error;
use zeroize::Zeroize;

use crate::{
    errors::{InternalError::InternalInvariantFailed, Result},
    utils::{k256_order, CurvePoint},
};

/// Generic elliptic curve point.
// TODO: remove From/Into/AsRef CurvePoint.
pub trait CT:
    Clone
    + Debug
    + Send
    + Sync
    + Eq
    + PartialEq
    + Into<EncodedPoint> // TODO: generalize.
    + From<ProjectivePoint> // TODO: generalize.
    + Serialize
    + for<'de> Deserialize<'de>
    + Add<Output = Self>
    + Zeroize
{
    /// A generator point.
    const GENERATOR: Self;

    /// The identity point, used to initialize the aggregation of a verification
    /// key
    const IDENTITY: Self;

    /// The type of scalars.
    type Scalar: ST;

    /// The order of the curve.
    fn order() -> BigNumber;

    /// Multiply `self` by a [`BigNumber`] point, which is first converted to
    /// the curve [`Scalar`] field (taken mod `q`, where `q` is the
    /// order of the curve).
    ///
    /// Note: This method ends up cloning the `point` value in the process of
    /// converting it. This may be insecure if the point contains private
    /// data.
    // TODO: name.
    fn scale(&self, scalar: &BigNumber) -> Result<Self>;

    /// Multiply the generator by a [`BigNumber`] scalar.
    fn scale_generator(scalar: &BigNumber) -> Result<Self>;

    /// Multiply `self` by a [`Scalar`].
    // TODO: name.
    fn scale2(&self, point: &Scalar) -> Self;

    /// Compute the x-projection of the point.
    fn x_projection(&self) -> Result<Scalar>;

    /// Serialize the point as an affine-encoded byte array.
    fn to_bytes(self) -> Vec<u8>;

    /// Deserialize a point from an affine-encoded byte array.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// Scalar trait.
pub trait ST {}

/// Default curve type.
pub type TestCT = CurvePoint;

/// Default scalar type.
pub type TestST = Scalar;

impl CT for CurvePoint {
    const GENERATOR: Self = CurvePoint::GENERATOR;
    const IDENTITY: Self = CurvePoint::IDENTITY;
    type Scalar = Scalar;

    fn order() -> BigNumber {
        k256_order()
    }

    fn scale(&self, scalar: &BigNumber) -> Result<Self> {
        self.multiply_by_bignum(scalar)
    }

    fn scale_generator(scalar: &BigNumber) -> Result<Self> {
        CurvePoint::GENERATOR.multiply_by_bignum(scalar)
    }

    fn scale2(&self, scalar: &Scalar) -> Self {
        self.multiply_by_scalar(scalar)
    }

    fn x_projection(&self) -> Result<Scalar> {
        let x_projection = self.x_affine();

        // Note: I don't think this is a foolproof transformation. The `from_repr`
        // method expects a scalar in the range `[0, q)`, but there's no
        // guarantee that the x-coordinate of `R` will be in that range.
        Option::from(Scalar::from_repr(x_projection)).ok_or_else(|| {
            error!("Unable to compute x-projection of curve point: failed to convert x coord to `Scalar`");
            InternalInvariantFailed
        })
    }

    fn to_bytes(self) -> Vec<u8> {
        CurvePoint::to_bytes(self)
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        CurvePoint::try_from_bytes(bytes)
    }
}

impl ST for Scalar {}
