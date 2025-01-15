//! Elliptic Curve abstraction

use generic_array::GenericArray;
use hmac::digest::core_api::CoreWrapper;
use k256::{
    ecdsa::{signature::DigestVerifier, VerifyingKey},
    elliptic_curve::{scalar::IsHigh, Field, PrimeField},
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar as K256_Scalar,
};
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use sha3::Keccak256Core;
use std::{fmt::Debug, ops::Add};
use tracing::error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    errors::{
        InternalError::{self, InternalInvariantFailed},
        Result,
    },
    utils::{k256_order, CurvePoint},
};

/// Generic elliptic curve point.
// TODO: remove From/Into/AsRef CurvePoint.
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
    type VK: VKT;

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
    fn try_from_bytes(bytes: &[u8]) -> Result<Self>;

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
}

pub trait SignatureTrait: Clone + Copy + Debug + PartialEq {
    fn from_scalars(r: &BigNumber, s: &BigNumber) -> Result<Self>
    where
        Self: Sized + Debug;

    // TODO: generalize RecoveryId
    //fn recover_id<C: CT>(
    //    &self,
    //    message: &[u8],
    //    public_key: &C::VK,
    //) -> Result<k256::ecdsa::RecoveryId>;
}

/// ECDSA signature on a message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CTSignature<C: CT>(k256::ecdsa::Signature, std::marker::PhantomData<C>);

/// Verifying Key trait
pub trait VKT: Clone + Copy + Debug + Send + Sync + Eq + PartialEq {
    fn from_point<C: CT>(point: C) -> Result<Self>;
    fn verify_signature<C: CT>(
        &self,
        digest: CoreWrapper<Keccak256Core>,
        signature: C::ECDSASignature,
    ) -> Result<()>;
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
        let bn_scalar: Self = <CurvePoint as CT>::bn_to_scalar(other).unwrap();
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
pub type TestCT = CurvePoint;

/// Default scalar type.
pub type TestST = K256_Scalar;

/// Default signature type.
pub type TestSignature = k256::ecdsa::Signature;

impl SignatureTrait for CTSignature<CurvePoint> {
    fn from_scalars(r: &BigNumber, s: &BigNumber) -> Result<Self> {
        let r_scalar = <CurvePoint as CT>::bn_to_scalar(r)?;
        let s_scalar = <CurvePoint as CT>::bn_to_scalar(s)?;
        let sig = k256::ecdsa::Signature::from_scalars(r_scalar, s_scalar)
            .map_err(|_| InternalInvariantFailed)?;
        Ok(CTSignature(sig, std::marker::PhantomData::<CurvePoint>))
    }
}

impl AsRef<k256::ecdsa::Signature> for CTSignature<CurvePoint> {
    fn as_ref(&self) -> &k256::ecdsa::Signature {
        &self.0
    }
}

impl CT for CurvePoint {
    const GENERATOR: Self = CurvePoint::GENERATOR;
    const IDENTITY: Self = CurvePoint::IDENTITY;
    type Scalar = K256_Scalar;
    type Encoded = EncodedPoint;
    type Projective = ProjectivePoint;
    type VK = VerifyingKey;
    type ECDSASignature = CTSignature<CurvePoint>;

    fn order() -> BigNumber {
        k256_order()
    }

    fn mul_by_bn(&self, scalar: &BigNumber) -> Result<Self> {
        self.multiply_by_bignum(scalar)
    }

    fn scale_generator(scalar: &BigNumber) -> Result<Self> {
        CurvePoint::GENERATOR.multiply_by_bignum(scalar)
    }

    fn mul(&self, scalar: &Self::Scalar) -> Self {
        self.multiply_by_scalar(scalar)
    }

    fn x_projection(&self) -> Result<Self::Scalar> {
        let x_projection = self.x_affine();

        // Note: I don't think this is a foolproof transformation. The `from_repr`
        // method expects a scalar in the range `[0, q)`, but there's no
        // guarantee that the x-coordinate of `R` will be in that range.
        Option::from(<k256::Scalar as PrimeField>::from_repr(x_projection)).ok_or_else(|| {
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

    // Returns x: BigNumber as a k256::Scalar mod k256_order
    fn bn_to_scalar(x: &BigNumber) -> Result<Self::Scalar> {
        // Take (mod q)
        let order = Self::order();

        let x_modded = x % order;

        let bytes = Zeroizing::new(x_modded.to_bytes());
        let mut slice = Zeroizing::new(vec![0u8; 32 - bytes.len()]);
        slice.extend_from_slice(&bytes);

        let mut ret: Self::Scalar = Option::from(<k256::Scalar as PrimeField>::from_repr(
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

    fn multiply_by_bignum(&self, point: &BigNumber) -> Result<Self> {
        let s = Zeroizing::new(Self::bn_to_scalar(point)?);
        let p = self.multiply_by_scalar(&s);
        Ok(p)
    }

    fn multiply_by_scalar(&self, point: &Self::Scalar) -> Self {
        self.multiply_by_scalar(point)
    }

    // Convert from k256::Scalar to BigNumber
    fn scalar_to_bn(x: &Self::Scalar) -> BigNumber {
        let bytes = x.to_repr();
        BigNumber::from_slice(bytes)
    }
}

impl VKT for VerifyingKey {
    fn from_point<C: CT>(point: C) -> Result<Self> {
        VerifyingKey::from_sec1_bytes(&point.to_bytes()).map_err(|_| InternalInvariantFailed)
    }

    fn verify_signature<C: CT>(
        &self,
        digest: CoreWrapper<Keccak256Core>,
        signature: C::ECDSASignature,
    ) -> Result<()> {
        self.verify_digest(digest, &signature)
            .map_err(|_| InternalInvariantFailed)
        /*let pk = self.to_encoded_point(false);
        VerifyingKey::from_encoded_point(&pk)
            .map_err(|_| InternalInvariantFailed)?
            .verify_digest(digest, &signature)
            .map_err(|_| InternalInvariantFailed)*/
    }
}

#[cfg(test)]
mod tests {
    use libpaillier::unknown_order::BigNumber;

    use crate::{
        curve::{TestCT, CT},
        utils::testing::init_testing,
    };

    #[test]
    fn test_bn_to_scalar_neg() {
        let _rng = init_testing();
        let neg1 = BigNumber::zero() - BigNumber::one();

        let scalar = TestCT::bn_to_scalar(&neg1).unwrap();
        assert_eq!(k256::Scalar::ZERO, scalar.add(&k256::Scalar::ONE));
    }
}
