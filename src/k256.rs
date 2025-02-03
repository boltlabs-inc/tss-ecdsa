//! K256 functions

use crate::{
    curve::{CurveTrait, ScalarTrait, Secp256k1, SignatureTrait, VerifyingKeyTrait},
    errors::{
        CallerError,
        InternalError::{self, InternalInvariantFailed},
        Result,
    },
};
use generic_array::GenericArray;
use k256::{
    ecdsa::{signature::DigestVerifier, VerifyingKey},
    elliptic_curve::{
        bigint::Encoding, group::GroupEncoding, point::AffineCoordinates, scalar::IsHigh,
        sec1::FromEncodedPoint, AffinePoint, Curve, CurveArithmetic, Field, Group, PrimeField,
    },
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar as K256_Scalar,
};
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Digest;
use sha3::Keccak256;
use std::{fmt::Debug, ops::Deref};
use tracing::error;
use zeroize::{Zeroize, Zeroizing};

/// Wrapper around k256::ProjectivePoint so that we can define our own
/// serialization/deserialization for it
///
/// Note that this type derives [`Debug`]; if a [`K256`] is used in a
/// private type, `Debug` should be manually implemented with the field of this
/// type explicitly redacted!
#[derive(Eq, PartialEq, Debug, Clone, Copy, Zeroize)]
pub struct K256(pub k256::ProjectivePoint);

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

    pub(crate) const GENERATOR: Self = K256(k256::ProjectivePoint::GENERATOR);
    /// The identity point, used to initialize the aggregation of a verification
    /// key
    pub const IDENTITY: Self = K256(k256::ProjectivePoint::IDENTITY);

    /// Multiply `self` by a [`BigNumber`] point, which is first converted to
    /// the secp256k1 [`K256_Scalar`] field (taken mod `q`, where `q` is the
    /// order of the curve).
    ///
    /// Note: This method ends up cloning the `point` value in the process of
    /// converting it. This may be insecure if the point contains private
    /// data.
    pub(crate) fn multiply_by_bignum(&self, point: &BigNumber) -> Result<Self> {
        let s = Zeroizing::new(Secp256k1::bn_to_scalar(point)?);
        let p = self.multiply_by_scalar(&s);
        Ok(p)
    }

    pub(crate) fn multiply_by_scalar(&self, point: &K256_Scalar) -> Self {
        Self(self.0 * point)
    }

    /// Serialize the `CurvePoint` as an affine-encoded secp256k1 byte array.
    pub(crate) fn to_bytes(self) -> Vec<u8> {
        let mut generic_array = AffinePoint::<k256::Secp256k1>::from(self.0).to_bytes();
        let bytes = generic_array.to_vec();
        generic_array.zeroize();
        bytes
    }

    pub(crate) fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut fixed_len_bytes: [u8; 33] = bytes.try_into().map_err(|_| {
            error!("Failed to encode bytes as a curve point");
            CallerError::DeserializationFailed
        })?;

        let point: Option<AffinePoint<k256::Secp256k1>> =
            AffinePoint::<k256::Secp256k1>::from_bytes(&fixed_len_bytes.into()).into();
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
        let afp = AffinePoint::<k256::Secp256k1>::from(self.0);
        afp.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for K256 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = AffinePoint::<k256::Secp256k1>::deserialize(deserializer)?;
        Ok(Self(p.into()))
    }
}

pub(crate) fn k256_order() -> BigNumber {
    // Set order = q
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    BigNumber::from_slice(order_bytes)
}

/// ECDSA signature on a message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SignatureK256<C: CurveTrait>(k256::ecdsa::Signature, std::marker::PhantomData<C>);
impl<C: CurveTrait> SignatureK256<C> {
    #[allow(dead_code)]
    pub(crate) fn recovery_id(&self, message: &[u8], public_key: &VerifyingKey) -> Result<u8> {
        let digest = Keccak256::new_with_prefix(message);
        let recover_id =
            k256::ecdsa::RecoveryId::trial_recovery_from_digest(public_key, digest, &self.0)
                .map_err(|e| {
                    error!("Failed to compute recovery ID for signature. Reason: {e:?}");
                    CallerError::SignatureTrialRecoveryFailed
                })?;
        Ok(recover_id.into())
    }
}

impl SignatureTrait for SignatureK256<K256> {
    fn from_scalars(r: &BigNumber, s: &BigNumber) -> Result<Self> {
        let r_scalar = <K256 as CurveTrait>::bn_to_scalar(r)?;
        let s_scalar = <K256 as CurveTrait>::bn_to_scalar(s)?;
        let sig = k256::ecdsa::Signature::from_scalars(r_scalar, s_scalar)
            .map_err(|_| InternalInvariantFailed)?;
        Ok(SignatureK256(sig, std::marker::PhantomData::<K256>))
    }
}

impl Deref for SignatureK256<K256> {
    type Target = k256::ecdsa::Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CurveTrait for K256 {
    const GENERATOR: Self = K256::GENERATOR;
    const IDENTITY: Self = K256::IDENTITY;
    type Scalar = K256_Scalar;
    type Encoded = EncodedPoint;
    type Projective = ProjectivePoint;
    type VerifyingKey = VerifyingKey;
    type ECDSASignature = SignatureK256<K256>;

    fn order() -> BigNumber {
        k256_order()
    }

    fn mul_by_bn(&self, scalar: &BigNumber) -> Result<Self> {
        self.multiply_by_bignum(scalar)
    }

    fn scale_generator(scalar: &BigNumber) -> Result<Self> {
        K256::GENERATOR.multiply_by_bignum(scalar)
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
        K256::to_bytes(self)
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        K256::try_from_bytes(bytes)
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

    // Random point.
    fn random() -> Self {
        let mut rng = rand::thread_rng();
        let random_point = ProjectivePoint::random(&mut rng);
        K256(random_point)
    }
}

impl ScalarTrait for K256_Scalar {
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
        let bn_scalar: Self = <K256 as CurveTrait>::bn_to_scalar(other).unwrap();
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

    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>> {
        Ok(<K256_Scalar as PrimeField>::from_repr(GenericArray::clone_from_slice(bytes)).into())
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

impl VerifyingKeyTrait for VerifyingKey {
    type C = K256;

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

    /// Add two verifying keys.
    fn add(&self, other: &Self) -> Self {
        let point1 = self.to_encoded_point(false);
        let point2 = other.to_encoded_point(false);
        let p1 = ProjectivePoint::from_encoded_point(&point1)
            .expect("Can not convert the first argument");
        let p2 = ProjectivePoint::from_encoded_point(&point2)
            .expect("Can not convert the second argument");
        let sum = p1 + p2;
        let sum_affine: ProjectivePoint =
            <k256::Secp256k1 as CurveArithmetic>::AffinePoint::from(sum).into();
        VerifyingKey::from_affine((&sum_affine).into())
            .expect("Can not convert the sum to verifying key")
    }
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
