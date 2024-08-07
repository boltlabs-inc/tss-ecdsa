// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::utils::CRYPTOGRAPHIC_RETRY_MAX;
use crate::errors::{CallerError, InternalError, Result};
use generic_array::GenericArray;
use k256::{
    elliptic_curve::{
        bigint::Encoding,
        group::{ff::PrimeField, GroupEncoding},
        point::AffineCoordinates,
        AffinePoint, Curve,
    },
    EncodedPoint, FieldBytes, Scalar, Secp256k1,
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;
use std::ops::Add;
use tracing::error;
use zeroize::Zeroize;

/// Wrapper around k256::ProjectivePoint so that we can define our own
/// serialization/deserialization for it
///
/// Note that this type derives [`Debug`]; if a [`CurvePoint`] is used in a
/// private type, `Debug` should be manually implemented with the field of this
/// type explicitly redacted!
#[derive(Eq, PartialEq, Debug, Clone, Copy, Zeroize)]
pub struct CurvePoint(k256::ProjectivePoint);

impl From<CurvePoint> for EncodedPoint {
    fn from(value: CurvePoint) -> EncodedPoint {
        value.0.to_affine().into()
    }
}

impl AsRef<CurvePoint> for CurvePoint {
    fn as_ref(&self) -> &CurvePoint {
        self
    }
}

impl<'de> CurvePoint {
    /// Get the x-coordinate of the curve point in affine representation.
    pub fn x_affine(&self) -> FieldBytes {
        self.0.to_affine().x()
    }
    #[cfg(test)]
    pub(crate) fn random(rng: impl RngCore) -> Self {
        use k256::{elliptic_curve::Group, ProjectivePoint};
        let random_point = ProjectivePoint::random(rng);
        CurvePoint(random_point)
    }
    pub(crate) const GENERATOR: Self = CurvePoint(k256::ProjectivePoint::GENERATOR);
    /// The identity point, used to initialize the aggregation of a verification
    /// key
    pub const IDENTITY: Self = CurvePoint(k256::ProjectivePoint::IDENTITY);

    /// Multiply `self` by a [`BigNumber`] point, which is first converted to
    /// the secp256k1 [`Scalar`] field (taken mod `q`, where `q` is the
    /// order of the curve).
    ///
    /// Note: This method ends up cloning the `point` value in the process of
    /// converting it. This may be insecure if the point contains private
    /// data.
    pub(crate) fn multiply_by_bignum(&self, point: &BigNumber) -> Result<Self> {
        Ok(self.multiply_by_scalar(&Self::bn_to_scalar(point)?))
    }

    pub(crate) fn multiply_by_scalar(&self, point: &Scalar) -> Self {
        Self(self.0 * point)
    }

    fn bn_to_scalar(x: &BigNumber) -> Result<Scalar> {

        // Take (mod q)
        let order = Self::curve_order();

        let x_modded = x % order;
        let bytes = x_modded.to_bytes();

        let mut slice = vec![0u8; 32 - bytes.len()];
        slice.extend_from_slice(&bytes);
        let mut ret: k256::Scalar = Option::from(k256::Scalar::from_repr(
            GenericArray::clone_from_slice(&slice),
        ))
        .ok_or_else(|| {
            error!("Failed to convert BigNumber into k256::Scalar");
            InternalError::InternalInvariantFailed
        })?;

        // Make sure to negate the scalar if the original input was negative
        if x < &BigNumber::zero() {
            ret = ret.negate();
        }

        Ok(ret)

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

impl std::ops::Add for CurvePoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
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

#[cfg(test)]
mod curve_point_tests {
    use crate::curve_point::{testing::init_testing, CurvePoint};
    use k256::elliptic_curve::Group;

    #[test]
    fn curve_point_byte_conversion_works() {
        let rng = &mut init_testing();
        let point = CurvePoint(k256::ProjectivePoint::random(rng));
        let bytes = point.to_bytes();
        let reconstructed = CurvePoint::try_from_bytes(&bytes).unwrap();
        assert_eq!(point, reconstructed);
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
        .ok_or(InternalError::CallingApplicationMistake(
            CallerError::RetryFailed,
        ))
}

/// Common trait for curves
pub trait CurveTrait: Serialize + Clone + Debug + Eq + PartialEq + Zeroize + Add<Output = Self> {
    /// Returns the generator of the curve
    fn generator() -> Self;
    /// Returns the identity element of the curve
    fn identity() -> Self;

    /// return the order of the curve
    fn curve_order() -> BigNumber;
    
    fn multiply_by_bignum(&self, point: &BigNumber) -> Result<Self> where Self: Sized;

    fn bn_to_scalar(x: &BigNumber) -> Result<Scalar>;
}

/// Implement the CurveTrait for the CurvePoint
impl CurveTrait for CurvePoint {

    fn generator() -> Self {
        CurvePoint::GENERATOR
    }

    fn identity() -> Self {
        CurvePoint::IDENTITY
    }

    fn curve_order() -> BigNumber {
        // Set order = q
        let order_bytes: [u8; 32] = CurvePoint::ORDER.to_be_bytes();
        BigNumber::from_slice(order_bytes)
    }

    fn multiply_by_bignum(&self, point: &BigNumber) -> Result<Self> {
        self.multiply_by_bignum(point)
    }
    
    fn bn_to_scalar(x: &BigNumber) -> Result<Scalar> {
        CurvePoint::bn_to_scalar(x)
    }
}

// Returns x: BigNumber as a k256::Scalar mod k256_order
//pub(crate) fn bn_to_scalar<C: CurveTrait>(x: &BigNumber) -> Result<k256::Scalar> {
/*pub(crate) fn bn_to_scalar(x: &BigNumber) -> Result<k256::Scalar> {
    // Take (mod q)
    //let order = C::curve_order();
    // Call curve_order() to get the order of the curve
    let order = k256_order();

    let x_modded = x % order;
    let bytes = x_modded.to_bytes();

    let mut slice = vec![0u8; 32 - bytes.len()];
    slice.extend_from_slice(&bytes);
    let mut ret: k256::Scalar = Option::from(k256::Scalar::from_repr(
        GenericArray::clone_from_slice(&slice),
    ))
    .ok_or_else(|| {
        error!("Failed to convert BigNumber into k256::Scalar");
        InternalError::InternalInvariantFailed
    })?;

    // Make sure to negate the scalar if the original input was negative
    if x < &BigNumber::zero() {
        ret = ret.negate();
    }

    Ok(ret)
}*/

pub(crate) fn k256_order() -> BigNumber {
    // Set order = q
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    BigNumber::from_slice(order_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::random_plusminus_by_size;
    use crate::curve_point::testing::init_testing;

    #[test]
    fn test_random_bn_in_range() {
        let mut rng = init_testing();
        // Statistical tests -- should generate random numbers that are long enough
        let mut max_len = 0;
        let num_bytes = 100;

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
        let _rng = init_testing();
        let neg1 = BigNumber::zero() - BigNumber::one();

        //let scalar = bn_to_scalar::<CurvePoint>(&neg1).unwrap();
        let scalar = CurvePoint::bn_to_scalar(&neg1).unwrap();
        assert_eq!(k256::Scalar::ZERO, scalar.add(&k256::Scalar::ONE));
    }
}

////////////////////////////
// Test Utility Functions //
////////////////////////////

/// Returns an rng to be used for testing. This will print the rng seed
/// to stderr so that if a test fails, the failing seed can be recovered
/// and used for debugging.
#[cfg(test)]
pub(crate) mod testing {
    use rand::{
        rngs::{OsRng, StdRng},
        Rng, SeedableRng,
    };
    use tracing_subscriber::{
        filter::Targets, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
    };

    /// Initialize any fields necessary for our tests. This should be called at
    /// the top of all our tests. This function is idempotent.
    ///
    /// This will print the rng seed to stderr so that if a test fails, the
    /// failing seed can be recovered and used for debugging.
    pub(crate) fn init_testing() -> StdRng {
        let mut seeder = OsRng;
        let seed = seeder.gen();
        eprintln!(
            "To re-run test with the same randomness, use init_testing_with_seed() with the following seed:"
        );
        eprintln!("\t{seed:?}");
        StdRng::from_seed(seed)
    }

    /// A seeded version of init_testing. Additionally, turns on logging by
    /// default.
    #[allow(unused)]
    pub(crate) fn init_testing_with_seed(seed: [u8; 32]) -> StdRng {
        let logging_level = EnvFilter::from_default_env()
            .max_level_hint()
            .unwrap()
            .into_level()
            .unwrap();

        // Only capture logging events from tss_ecdsa crate.
        let targets = Targets::new().with_target("tss_ecdsa", logging_level);
        let stdout_layer = tracing_subscriber::fmt::layer()
            .pretty()
            .with_filter(targets);

        // It's okay if this fails. It just means logging has already been set up for
        // this thread.
        let _ = tracing_subscriber::registry().with(stdout_layer).try_init();

        // Return RNG
        StdRng::from_seed(seed)
    }
}
