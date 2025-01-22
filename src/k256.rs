//! K256 functions

use crate::{
    curve::{TestCT, CT},
    errors::{CallerError, Result},
};
use k256::{
    elliptic_curve::{
        bigint::Encoding, group::GroupEncoding, point::AffineCoordinates, AffinePoint, Curve,
    },
    EncodedPoint, FieldBytes, Scalar, Secp256k1,
};
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;
use tracing::error;
use zeroize::{Zeroize, Zeroizing};

/// Wrapper around k256::ProjectivePoint so that we can define our own
/// serialization/deserialization for it
///
/// Note that this type derives [`Debug`]; if a [`K256`] is used in a
/// private type, `Debug` should be manually implemented with the field of this
/// type explicitly redacted!
#[derive(Eq, PartialEq, Debug, Clone, Copy, Zeroize)]
pub struct K256(k256::ProjectivePoint);

impl From<K256> for EncodedPoint {
    fn from(value: K256) -> EncodedPoint {
        value.0.to_affine().into()
    }
}

impl AsRef<K256> for K256 {
    fn as_ref(&self) -> &K256 {
        self
    }
}

impl K256 {
    /// Get the x-coordinate of the curve point
    pub fn x_affine(&self) -> FieldBytes {
        self.0.to_affine().x()
    }

    #[cfg(test)]
    pub(crate) fn random(rng: impl rand::RngCore) -> Self {
        use k256::{elliptic_curve::Group, ProjectivePoint};
        let random_point = ProjectivePoint::random(rng);
        K256(random_point)
    }
    pub(crate) const GENERATOR: Self = K256(k256::ProjectivePoint::GENERATOR);
    /// The identity point, used to initialize the aggregation of a verification
    /// key
    pub const IDENTITY: Self = K256(k256::ProjectivePoint::IDENTITY);

    /// Multiply `self` by a [`BigNumber`] point, which is first converted to
    /// the secp256k1 [`Scalar`] field (taken mod `q`, where `q` is the
    /// order of the curve).
    ///
    /// Note: This method ends up cloning the `point` value in the process of
    /// converting it. This may be insecure if the point contains private
    /// data.
    pub(crate) fn multiply_by_bignum(&self, point: &BigNumber) -> Result<Self> {
        let s = Zeroizing::new(TestCT::bn_to_scalar(point)?);
        let p = self.multiply_by_scalar(&s);
        Ok(p)
    }

    pub(crate) fn multiply_by_scalar(&self, point: &Scalar) -> Self {
        Self(self.0 * point)
    }

    /// Serialize the `CurvePoint` as an affine-encoded secp256k1 byte array.
    pub(crate) fn to_bytes(self) -> Vec<u8> {
        let mut generic_array = AffinePoint::<Secp256k1>::from(self.0).to_bytes();
        let bytes = generic_array.to_vec();
        generic_array.zeroize();
        bytes
    }

    pub(crate) fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut fixed_len_bytes: [u8; 33] = bytes.try_into().map_err(|_| {
            error!("Failed to encode bytes as a curve point");
            CallerError::DeserializationFailed
        })?;

        let point: Option<AffinePoint<Secp256k1>> =
            AffinePoint::<Secp256k1>::from_bytes(&fixed_len_bytes.into()).into();
        fixed_len_bytes.zeroize();

        match point {
            Some(point) => Ok(Self(point.into())),
            None => {
                error!("Failed to encode bytes as a curve point");
                Err(CallerError::DeserializationFailed)?
            }
        }
    }
}

impl std::ops::Add for K256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl From<k256::ProjectivePoint> for K256 {
    fn from(p: k256::ProjectivePoint) -> Self {
        Self(p)
    }
}

impl Serialize for K256 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let afp = AffinePoint::<Secp256k1>::from(self.0);
        afp.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for K256 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = AffinePoint::<Secp256k1>::deserialize(deserializer)?;
        Ok(Self(p.into()))
    }
}

pub(crate) fn k256_order() -> BigNumber {
    // Set order = q
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    BigNumber::from_slice(order_bytes)
}

#[cfg(test)]
mod curve_point_tests {
    use crate::{k256::K256, utils::testing::init_testing};
    use k256::elliptic_curve::Group;

    #[test]
    fn curve_point_byte_conversion_works() {
        let rng = &mut init_testing();
        let point = K256(k256::ProjectivePoint::random(rng));
        let bytes = point.to_bytes();
        let reconstructed = K256::try_from_bytes(&bytes).unwrap();
        assert_eq!(point, reconstructed);
    }
}
