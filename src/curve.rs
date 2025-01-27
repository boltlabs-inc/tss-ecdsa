//! Elliptic Curve abstraction
use crate::{errors::Result, k256::K256, p256::P256};
use generic_array::GenericArray;
use hmac::digest::core_api::CoreWrapper;
use k256::{
    elliptic_curve::{scalar::IsHigh, Field, PrimeField},
    FieldBytes, Scalar as K256_Scalar,
};
use libpaillier::unknown_order::BigNumber;
use p256::Scalar as P256_Scalar;
use serde::{Deserialize, Serialize};
use sha3::Keccak256Core;
use std::{fmt::Debug, ops::Add};
use zeroize::Zeroize;

/// Generic elliptic curve point.
pub trait CT:
    Clone
    + Copy
    + Debug
    + Send
    + Sync
    + Eq
    + PartialEq
    + Into<Self::Encoded>
    + From<Self::Projective>
    + Serialize
    + for<'de> Deserialize<'de>
    + Add<Output = Self>
    + Zeroize
    + AsRef<Self>
{
    /// A generator point.
    const GENERATOR: Self;

    /// The identity point, used to initialize the aggregation of a verification
    /// key
    const IDENTITY: Self;

    /// The type of scalars.
    type Scalar: ST;

    /// The encoded point type.
    type Encoded;

    /// The projective point type.
    type Projective;

    /// The ECDSA Verifying Key
    type VK: VKT<C = Self>;

    /// The ECDSA Signature type
    type ECDSASignature: SignatureTrait;

    /// The order of the curve.
    fn order() -> BigNumber;

    /// Multiply `self` by a [`BigNumber`] point, which is first converted to
    /// the curve [`Self::Scalar`] field (taken mod `q`, where `q` is the
    /// order of the curve).
    ///
    /// Note: This method ends up cloning the `point` value in the process of
    /// converting it. This may be insecure if the point contains private
    /// data.
    fn mul_by_bn(&self, scalar: &BigNumber) -> Result<Self>;

    /// Multiply the generator by a [`BigNumber`] scalar.
    fn scale_generator(scalar: &BigNumber) -> Result<Self>;

    /// Multiply `self` by a [`Self::Scalar`].
    fn mul(&self, point: &Self::Scalar) -> Self;

    /// Compute the x-projection of the point.
    fn x_projection(&self) -> Result<Self::Scalar>;

    /// Serialize the point as an affine-encoded byte array.
    fn to_bytes(self) -> Vec<u8>;

    /// Deserialize a point from an affine-encoded byte array.
    fn try_from_bytes_ct(bytes: &[u8]) -> Result<Self>;

    /// Convert BigNumber to Scalar.
    fn bn_to_scalar(bn: &BigNumber) -> Result<Self::Scalar>;

    /// Multiply `self` by a [`BigNumber`] point, which is first converted to
    /// the subjacent [`Self::Scalar`] field (taken mod `q`, where `q` is the
    /// order of the curve).
    fn multiply_by_bignum(&self, point: &BigNumber) -> Result<Self>;

    /// Multiply `self` by a [`Self::Scalar`].
    fn multiply_by_scalar(&self, point: &Self::Scalar) -> Self;

    /// Convert from `[Self::Scalar]` to BigNumber
    fn scalar_to_bn(x: &Self::Scalar) -> BigNumber;

    /// Random scalar.
    fn random() -> Self;

    /// Convert to Verifying Key.
    fn to_vk(&self) -> Result<Self::VK> {
        Self::VK::from_point(*self)
    }
}

/// Signature trait.
pub trait SignatureTrait: Clone + Copy + Debug + PartialEq {
    /// Create a signature from two scalars.
    fn from_scalars(r: &BigNumber, s: &BigNumber) -> Result<Self>
    where
        Self: Sized + Debug;
}

/// Verifying Key trait
pub trait VKT: Clone + Copy + Debug + Send + Sync + Eq + PartialEq {
    /// The curve associated with this verifying key.
    type C: CT;

    /// Create a verifying key from a curve point.
    fn from_point(point: Self::C) -> Result<Self>;

    /// Verify the signature against the given digest output.
    fn verify_signature(
        &self,
        digest: CoreWrapper<Keccak256Core>,
        signature: <Self::C as CT>::ECDSASignature,
    ) -> Result<()>;

    /// Add two verifying keys.
    fn add(&self, other: &Self) -> Self;
}

/// Scalar trait.
pub trait ST:
    Sync
    + Send
    + Clone
    + Copy
    + Debug
    + PartialEq
    + PartialOrd
    + Eq
    + Zeroize
    + Serialize
    + for<'de> Deserialize<'de>
    + Add<Output = Self>
    + AsRef<Self>
    + Into<FieldBytes>
{
    /// Return the zero scalar.
    fn zero() -> Self;

    /// Return the one scalar.
    fn one() -> Self;

    /// Convert a u128 to a scalar.
    fn convert_from_u128(x: u128) -> Self;

    /// Add two scalars.
    fn add(&self, other: &Self) -> Self;

    /// Addition operator such that we can use += syntax.
    fn add_assign(&mut self, other: Self) {
        *self = self.add(other);
    }

    /// Sub two scalars.
    fn sub(&self, other: &Self) -> Self;

    /// Negate
    fn negate(&self) -> Self;

    /// Multiply two scalars.
    fn mul(&self, other: &Self) -> Self;

    /// Implement the mul operator such that we can use *= syntax.
    fn mul_assign(&mut self, other: &Self) {
        *self = self.mul(other);
    }

    /// Multiply by a BigNumber.
    fn mul_bignum(&self, other: &BigNumber) -> Self;

    /// True if and only if self is larger than n/2
    fn is_high(&self) -> bool;

    /// Random scalar.
    fn random() -> Self;

    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Convert from bytes
    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    /// Convert from repr
    fn from_repr(bytes: Vec<u8>) -> Self;

    /// Return the modulus of the scalar.
    fn modulus(&self) -> BigNumber;

    /// Invert the scalar.
    fn invert(&self) -> Option<Self>;
}

impl ST for K256_Scalar {
    fn zero() -> Self {
        K256_Scalar::ZERO
    }

    fn one() -> Self {
        K256_Scalar::ONE
    }

    fn convert_from_u128(x: u128) -> Self {
        K256_Scalar::from_u128(x)
    }

    fn add(&self, other: &Self) -> Self {
        k256::Scalar::add(self, other)
    }

    fn sub(&self, other: &Self) -> Self {
        k256::Scalar::sub(self, other)
    }

    fn negate(&self) -> Self {
        k256::Scalar::negate(self)
    }

    fn mul(&self, other: &Self) -> Self {
        k256::Scalar::mul(self, other)
    }

    fn mul_bignum(&self, other: &BigNumber) -> Self {
        // use bn_to_scalar to convert other to a scalar
        let bn_scalar: Self = <K256 as CT>::bn_to_scalar(other).unwrap();
        k256::Scalar::mul(self, &bn_scalar)
    }

    fn is_high(&self) -> bool {
        <k256::Scalar as IsHigh>::is_high(self).into()
    }

    fn random() -> Self {
        let rng = rand::thread_rng();
        <K256_Scalar as Field>::random(rng)
    }

    fn to_bytes(&self) -> Vec<u8> {
        K256_Scalar::to_bytes(self).to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <K256_Scalar as PrimeField>::from_repr(GenericArray::clone_from_slice(bytes)).into()
    }

    fn from_repr(bytes: Vec<u8>) -> Self {
        <K256_Scalar as PrimeField>::from_repr(GenericArray::clone_from_slice(&bytes)).unwrap()
    }

    fn modulus(&self) -> BigNumber {
        BigNumber::from_slice(<K256_Scalar as PrimeField>::MODULUS)
    }

    fn invert(&self) -> Option<Self> {
        K256_Scalar::invert(self).into()
    }
}

/// Default curve type.
pub type TestCT = K256;
//pub type TestCT = P256;

/// Default scalar type.
pub type TestST = K256_Scalar;
//pub type TestST = P256_Scalar;

/// Default signature type.
pub type TestSignature = k256::ecdsa::Signature;

/// K256 curve type.
pub type Secp256k1 = K256;

/// P256 curve type.
pub type Secp256r1 = P256;

/// P256 scalar type.
pub type P256Scalar = P256_Scalar;

#[cfg(test)]
mod tests {
    use libpaillier::unknown_order::BigNumber;

    use crate::{
        curve::{TestCT, CT, ST},
        utils::testing::init_testing,
    };

    #[test]
    fn test_bn_to_scalar_neg() {
        let _rng = init_testing();
        let neg1 = BigNumber::zero() - BigNumber::one();

        let scalar = TestCT::bn_to_scalar(&neg1).unwrap();
        assert_eq!(
            <TestCT as CT>::Scalar::zero(),
            scalar.add(&<TestCT as CT>::Scalar::one())
        );
    }
}
