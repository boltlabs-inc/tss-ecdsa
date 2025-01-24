//! Elliptic Curve abstraction
use crate::{
    errors::{
        CallerError,
        InternalError::{self, InternalInvariantFailed},
        Result,
    },
    k256::{k256_order, K256},
    p256::P256,
};
use generic_array::GenericArray;
use hmac::digest::core_api::CoreWrapper;
use k256::{
    ecdsa::{signature::DigestVerifier, VerifyingKey},
    elliptic_curve::{
        scalar::IsHigh, sec1::FromEncodedPoint, CurveArithmetic, Field, Group, PrimeField,
    },
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar as K256_Scalar,
};
use libpaillier::unknown_order::BigNumber;
use p256::Scalar as P256_Scalar;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha3::{Keccak256, Keccak256Core};
use std::{
    fmt::Debug,
    ops::{Add, Deref},
};
use tracing::error;
use zeroize::{Zeroize, Zeroizing};

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

/// ECDSA signature on a message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CTSignatureK256<C: CT>(k256::ecdsa::Signature, std::marker::PhantomData<C>);
impl<C: CT> CTSignatureK256<C> {
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
//pub type TestCT = K256;
pub type TestCT = P256;

/// Default scalar type.
//pub type TestST = K256_Scalar;
pub type TestST = P256_Scalar;

/// Default signature type.
pub type TestSignature = k256::ecdsa::Signature;

/// K256 curve type.
pub type Secp256k1 = K256;

/// P256 curve type.
pub type Secp256r1 = P256;

/// P256 scalar type.
pub type P256Scalar = P256_Scalar;

impl SignatureTrait for CTSignatureK256<K256> {
    fn from_scalars(r: &BigNumber, s: &BigNumber) -> Result<Self> {
        let r_scalar = <K256 as CT>::bn_to_scalar(r)?;
        let s_scalar = <K256 as CT>::bn_to_scalar(s)?;
        let sig = k256::ecdsa::Signature::from_scalars(r_scalar, s_scalar)
            .map_err(|_| InternalInvariantFailed)?;
        Ok(CTSignatureK256(sig, std::marker::PhantomData::<K256>))
    }
}

impl Deref for CTSignatureK256<K256> {
    type Target = k256::ecdsa::Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CT for K256 {
    const GENERATOR: Self = K256::GENERATOR;
    const IDENTITY: Self = K256::IDENTITY;
    type Scalar = K256_Scalar;
    type Encoded = EncodedPoint;
    type Projective = ProjectivePoint;
    type VK = VerifyingKey;
    type ECDSASignature = CTSignatureK256<K256>;

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

    fn try_from_bytes_ct(bytes: &[u8]) -> Result<Self> {
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

impl VKT for VerifyingKey {
    type C = K256;

    fn from_point(point: Self::C) -> Result<Self> {
        VerifyingKey::from_sec1_bytes(&point.to_bytes()).map_err(|_| InternalInvariantFailed)
    }

    fn verify_signature(
        &self,
        digest: Keccak256,
        signature: <Self::C as CT>::ECDSASignature,
    ) -> Result<()> {
        self.verify_digest(digest, signature.deref())
            .map_err(|_| InternalInvariantFailed)
    }

    /// Add two verifying keys.
    fn add(&self, other: &Self) -> Self {
        //let point = self.to_encoded_point(false);
        //let other_point = other.to_encoded_point(false);
        //let sum = point.add(&other_point).unwrap();
        //VerifyingKey::from_encoded_point(&sum).unwrap()
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
