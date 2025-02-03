//! P256 functions

use crate::{
    curve::{CurveTrait, ScalarTrait, Secp256r1, SignatureTrait, VerifyingKeyTrait},
    errors::{
        CallerError,
        InternalError::{self, InternalInvariantFailed},
        Result,
    },
};
use generic_array::GenericArray;
use libpaillier::unknown_order::BigNumber;
use p256::{
    ecdsa::{signature::DigestVerifier, VerifyingKey},
    elliptic_curve::{
        bigint::Encoding, group::GroupEncoding, point::AffineCoordinates, scalar::IsHigh,
        sec1::FromEncodedPoint, AffinePoint, Curve, CurveArithmetic, Field, Group, PrimeField,
    },
    EncodedPoint, FieldBytes, NistP256, ProjectivePoint, Scalar as P256_Scalar,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::Keccak256;
use std::{
    fmt::Debug,
    ops::{Deref, Neg},
};
use tracing::error;
use zeroize::{Zeroize, Zeroizing};

/// Wrapper around p256::ProjectivePoint so that we can define our own
/// serialization/deserialization for it
///
/// Note that this type derives [`Debug`]; if a [`P256`] is used in a
/// private type, `Debug` should be manually implemented with the field of this
/// type explicitly redacted!
#[derive(Eq, PartialEq, Debug, Clone, Copy, Zeroize)]
pub struct P256(pub p256::ProjectivePoint);

impl From<P256> for EncodedPoint {
    fn from(value: P256) -> EncodedPoint {
        value.0.to_affine().into()
    }
}

impl AsRef<P256> for P256 {
    fn as_ref(&self) -> &P256 {
        self
    }
}

/// ECDSA signature on a message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SignatureP256<C: CurveTrait>(p256::ecdsa::Signature, std::marker::PhantomData<C>);
impl<C: CurveTrait> SignatureP256<C> {
    #[allow(dead_code, unused_variables)]
    pub(crate) fn recovery_id(&self, _message: &[u8], _public_key: &VerifyingKey) -> Result<u8> {
        todo!()
    }
}

impl P256 {
    /// Get the x-coordinate of the curve point
    pub fn x_affine(&self) -> FieldBytes {
        self.0.to_affine().x()
    }

    pub(crate) const GENERATOR: Self = P256(p256::ProjectivePoint::GENERATOR);
    /// The identity point, used to initialize the aggregation of a verification
    /// key
    pub const IDENTITY: Self = P256(p256::ProjectivePoint::IDENTITY);

    /// Multiply `self` by a [`BigNumber`] point, which is first converted to
    /// the secp256k1 [`P256_Scalar`] field (taken mod `q`, where `q` is the
    /// order of the curve).
    ///
    /// Note: This method ends up cloning the `point` value in the process of
    /// converting it. This may be insecure if the point contains private
    /// data.
    pub(crate) fn multiply_by_bignum(&self, point: &BigNumber) -> Result<Self> {
        let s = Zeroizing::new(<Secp256r1 as CurveTrait>::bn_to_scalar(point)?);
        let p = self.multiply_by_scalar(&s);
        Ok(p)
    }

    pub(crate) fn multiply_by_scalar(&self, point: &P256_Scalar) -> Self {
        Self(self.0 * point)
    }

    /// Serialize the `CurvePoint` as an affine-encoded secp256r1 byte array.
    pub(crate) fn to_bytes(self) -> Vec<u8> {
        let mut generic_array = AffinePoint::<NistP256>::from(self.0).to_bytes();
        let bytes = generic_array.to_vec();
        generic_array.zeroize();
        bytes
    }

    pub(crate) fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut fixed_len_bytes: [u8; 33] = bytes.try_into().map_err(|_| {
            error!("Failed to encode bytes as a curve point");
            CallerError::DeserializationFailed
        })?;

        let point: Option<AffinePoint<p256::NistP256>> =
            AffinePoint::<p256::NistP256>::from_bytes(&fixed_len_bytes.into()).into();
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

impl std::ops::Add for P256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl From<p256::ProjectivePoint> for P256 {
    fn from(p: p256::ProjectivePoint) -> Self {
        Self(p)
    }
}

impl Serialize for P256 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let afp = AffinePoint::<NistP256>::from(self.0);
        let bytes = afp.to_bytes();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for P256 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = AffinePoint::<NistP256>::deserialize(deserializer)?;
        Ok(Self(p.into()))
    }
}

pub(crate) fn p256_order() -> BigNumber {
    // Set order = q
    let order_bytes: [u8; 32] = p256::NistP256::ORDER.to_be_bytes();
    BigNumber::from_slice(order_bytes)
}

impl CurveTrait for P256 {
    const GENERATOR: Self = P256::GENERATOR;
    const IDENTITY: Self = P256::IDENTITY;
    type Scalar = P256_Scalar;
    type Encoded = EncodedPoint;
    type Projective = ProjectivePoint;
    type VerifyingKey = VerifyingKey;
    type ECDSASignature = SignatureP256<P256>;

    fn order() -> BigNumber {
        p256_order()
    }

    fn mul_by_bn(&self, scalar: &BigNumber) -> Result<Self> {
        self.multiply_by_bignum(scalar)
    }

    fn scale_generator(scalar: &BigNumber) -> Result<Self> {
        P256::GENERATOR.multiply_by_bignum(scalar)
    }

    fn mul(&self, scalar: &Self::Scalar) -> Self {
        self.multiply_by_scalar(scalar)
    }

    fn x_projection(&self) -> Result<Self::Scalar> {
        let x_projection = self.x_affine();

        // Note: I don't think this is a foolproof transformation. The `from_repr`
        // method expects a scalar in the range `[0, q)`, but there's no
        // guarantee that the x-coordinate of `R` will be in that range.
        Option::from(<p256::Scalar as PrimeField>::from_repr(x_projection)).ok_or_else(|| {
            error!("Unable to compute x-projection of curve point: failed to convert x coord to `Scalar`");
            InternalError::InternalInvariantFailed
        })
    }

    fn to_bytes(self) -> Vec<u8> {
        P256::to_bytes(self)
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        P256::try_from_bytes(bytes)
    }

    // Returns x: BigNumber as a P256::Scalar mod P256_order
    fn bn_to_scalar(x: &BigNumber) -> Result<Self::Scalar> {
        // Take (mod q)
        let order = Self::order();

        let x_modded = x % order;

        let bytes = Zeroizing::new(x_modded.to_bytes());
        let mut slice = Zeroizing::new(vec![0u8; 32 - bytes.len()]);
        slice.extend_from_slice(&bytes);

        let mut ret: Self::Scalar = Option::from(<p256::Scalar as PrimeField>::from_repr(
            GenericArray::clone_from_slice(&slice),
        ))
        .ok_or_else(|| {
            error!("Failed to convert BigNumber into p256::Scalar");
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

    // Convert from p256::Scalar to BigNumber
    fn scalar_to_bn(x: &Self::Scalar) -> BigNumber {
        let bytes = x.to_repr();
        BigNumber::from_slice(bytes)
    }

    // Random point
    fn random() -> Self {
        let rng = rand::thread_rng();
        P256(p256::ProjectivePoint::random(rng))
    }
}

impl ScalarTrait for P256_Scalar {
    fn zero() -> Self {
        P256_Scalar::ZERO
    }

    fn one() -> Self {
        P256_Scalar::ONE
    }

    fn convert_from_u128(x: u128) -> Self {
        P256_Scalar::from_u128(x)
    }

    fn add(&self, other: &Self) -> Self {
        p256::Scalar::add(self, other)
    }

    fn sub(&self, other: &Self) -> Self {
        p256::Scalar::sub(self, other)
    }

    fn negate(&self) -> Self {
        p256::Scalar::neg(*self)
    }

    fn mul(&self, other: &Self) -> Self {
        //p256::Scalar::mul(self, other)
        p256::Scalar::multiply(self, other)
    }

    fn mul_bignum(&self, other: &BigNumber) -> Self {
        // use bn_to_scalar to convert other to a scalar
        let bn_scalar: Self = <P256 as CurveTrait>::bn_to_scalar(other).unwrap();
        p256::Scalar::mul(self, &bn_scalar)
    }

    fn is_high(&self) -> bool {
        <p256::Scalar as IsHigh>::is_high(self).into()
    }

    fn random() -> Self {
        let rng = rand::thread_rng();
        <P256_Scalar as Field>::random(rng)
    }

    fn to_bytes(&self) -> Vec<u8> {
        P256_Scalar::to_bytes(self).to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>> {
        Ok(<P256_Scalar as PrimeField>::from_repr(GenericArray::clone_from_slice(bytes)).into())
    }

    fn from_repr(bytes: Vec<u8>) -> Self {
        <P256_Scalar as PrimeField>::from_repr(GenericArray::clone_from_slice(&bytes)).unwrap()
    }

    fn modulus(&self) -> BigNumber {
        BigNumber::from_slice(<P256_Scalar as PrimeField>::MODULUS)
    }

    fn invert(&self) -> Option<Self> {
        P256_Scalar::invert(self).into()
    }
}

impl SignatureTrait for SignatureP256<P256> {
    fn from_scalars(r: &BigNumber, s: &BigNumber) -> Result<Self> {
        let r_scalar = <P256 as CurveTrait>::bn_to_scalar(r)?;
        let s_scalar = <P256 as CurveTrait>::bn_to_scalar(s)?;
        let sig = p256::ecdsa::Signature::from_scalars(r_scalar, s_scalar)
            .map_err(|_| InternalInvariantFailed)?;
        Ok(SignatureP256(sig, std::marker::PhantomData::<P256>))
    }
}

impl Deref for SignatureP256<P256> {
    type Target = p256::ecdsa::Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl VerifyingKeyTrait for VerifyingKey {
    type C = P256;

    fn from_point(point: Self::C) -> Result<Self> {
        VerifyingKey::from_sec1_bytes(&point.to_bytes()).map_err(|_| InternalInvariantFailed)
    }

    fn verify_signature(
        &self,
        digest: Keccak256,
        signature: <Self::C as CurveTrait>::ECDSASignature,
    ) -> Result<()> {
        self.verify_digest(digest, signature.deref())
            .map_err(|_| InternalInvariantFailed)
    }

    // Add two verifying keys
    fn add(&self, other: &Self) -> Self {
        let point1 = self.to_encoded_point(false);
        let point2 = other.to_encoded_point(false);
        let p1 = ProjectivePoint::from_encoded_point(&point1)
            .expect("Can not convert the first argument");
        let p2 = ProjectivePoint::from_encoded_point(&point2)
            .expect("Can not convert the second argument");
        let sum = p1 + p2;
        let sum_affine: ProjectivePoint =
            <NistP256 as CurveArithmetic>::AffinePoint::from(sum).into();
        VerifyingKey::from_affine((&sum_affine).into())
            .expect("Can not convert the sum to verifying key")
    }
}

#[cfg(test)]
mod curve_point_tests {
    use crate::{p256::P256, utils::testing::init_testing};
    use p256::elliptic_curve::Group;

    #[test]
    fn curve_point_byte_conversion_works() {
        let rng = &mut init_testing();
        let point = P256(p256::ProjectivePoint::random(rng));
        let bytes = point.to_bytes();
        let reconstructed = P256::try_from_bytes(&bytes).unwrap();
        assert_eq!(point, reconstructed);
    }
}
