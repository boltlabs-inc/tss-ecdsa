use crate::{errors::InternalError, utils};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::error;

/// Tool for verifying and operating on elements of the multiplicative
/// group of integers mod `N`, for some modulus `N`.
///
/// The builder defines the modulus `N` for all [`ZStarN`] that it creates.
/// This simplifies the `ZStarN` type and allows it to be serialized _without_
/// duplicating the modulus.
#[derive(Serialize)]
struct ZStarNBuilder {
    modulus: BigNumber,
}
#[allow(unused)]
impl ZStarNBuilder {
    pub fn new(n: BigNumber) -> Self {
        ZStarNBuilder { modulus: n }
    }
    /// Construct an element of [`ZStarN`] by validating that an unverified
    /// instance of [`ZStarNUnverified`] is properly constructed with
    /// respect to the current [`ZStarNBuilder`]. This is one of two ways of
    /// constructing elements of [`ZStarN`]. The other way is by randomly
    /// sampling the element in the multiplicative group modulo n.
    pub fn validate(&self, unverified: ZStarNUnverified) -> Result<ZStarN, InternalError> {
        if unverified.value().is_zero() {
            error!("Elements of the multiplicative group  ZK*_N cannot be zero");
            return Err(InternalError::ProtocolError);
        } else if unverified.value() > self.modulus() {
            error!(
                "Elements of the multiplicative group ZK*_N cannot be larger than the RSA modulus"
            );
            return Err(InternalError::ProtocolError);
        } else if unverified.value() < &BigNumber::zero() {
            error!("Elements of the multiplicative group ZK*_N cannot be negative");
            return Err(InternalError::ProtocolError);
        }
        let result = unverified.value().gcd(self.modulus());
        if result != BigNumber::one() {
            error!("Elements are not coprime");
            return Err(InternalError::ProtocolError);
        }
        Ok(ZStarN {
            value: unverified.value().to_owned(),
            builder: self,
        })
    }
    /// Return the modulus of [`ZStarNBuilder`].
    fn modulus(&self) -> &BigNumber {
        &self.modulus
    }
}

/// A elements in the multiplicative group modulo `N` as defined by
/// [`ZStarNBuilder`].
///
/// Elements of this group are in the interval (0, N) and validated to be as
/// such.
#[derive(Serialize)]
struct ZStarN<'a> {
    value: BigNumber,
    builder: &'a ZStarNBuilder,
}
#[allow(unused)]
impl<'a> ZStarN<'a> {
    /// Return the value stored in [`ZStarN`].
    fn as_bignumber(&self) -> &BigNumber {
        &self.value
    }
    fn serialize(&self) -> Result<Vec<u8>, InternalError> {
        serialize!(self.as_bignumber())
    }
    /// Randomly samples an element of the multiplicative group modulo N (as
    /// defined by the builder).
    ///
    /// This is one of two ways of constructing an element [`ZStarN`].
    /// The other way is by validating an instance of [`ZStarNUnverified`].
    fn random_element<R: RngCore + CryptoRng>(
        builder: &'a ZStarNBuilder,
        rng: &mut R,
    ) -> Result<Self, InternalError> {
        utils::random_bn_in_z_star(rng, builder.modulus()).map(|value| Self { value, builder })
    }
}
/// Unverified, deserialized value that claims to be in the multiplicative
/// group of integers mod `N`, for some modulus `N`.
///
/// This can be verified into a valid [`ZStarN`] using a [`ZStarNBuilder`].
#[derive(Deserialize)]
struct ZStarNUnverified {
    value: BigNumber,
}
#[allow(unused)]
impl ZStarNUnverified {
    #[cfg(test)]
    fn new(value: BigNumber) -> Self {
        ZStarNUnverified { value }
    }
    fn value(&self) -> &BigNumber {
        &self.value
    }
}

#[cfg(test)]
mod test {
    use crate::{paillier::DecryptionKey, utils::testing::init_testing, zkstar::*};

    #[test]
    fn zkstar_verification_works() {
        let mut rng = init_testing();
        let (_, p, q) = DecryptionKey::new(&mut rng).unwrap();
        let builder = ZStarNBuilder::new(&p * &q);

        let value_verifies = ZStarNUnverified::new((&p - 1) / 2);
        let zstar_verifies = builder.validate(value_verifies);
        assert!(zstar_verifies.is_ok());

        // Edge case
        let value_verifies_one = ZStarNUnverified::new(BigNumber::one());
        let zstar_verifies_one = builder.validate(value_verifies_one);
        assert!(zstar_verifies_one.is_ok());
    }

    #[test]
    fn zkstar_constructor_rejects_elements_outside_group() {
        let mut rng = init_testing();
        let (_, p, q) = DecryptionKey::new(&mut rng).unwrap();
        let builder = ZStarNBuilder::new(&p * &q);

        let value_fails = ZStarNUnverified::new(q.clone());
        let zstar_fails = builder.validate(value_fails);
        assert!(zstar_fails.is_err());

        let value_fails_zero = ZStarNUnverified::new(BigNumber::zero());
        let zstar_fails_zero = builder.validate(value_fails_zero);
        assert!(zstar_fails_zero.is_err());

        // Edge cases
        let value_fails_zero = ZStarNUnverified::new(BigNumber::zero());
        let zstar_fails_zero = builder.validate(value_fails_zero);
        assert!(zstar_fails_zero.is_err());

        let value_fails_n = ZStarNUnverified::new(&p * &q);
        let zstar_fails_n = builder.validate(value_fails_n);
        assert!(zstar_fails_n.is_err());

        let value_fails_neg: ZStarNUnverified = ZStarNUnverified::new(-BigNumber::one());
        let zstar_fails__neg = builder.validate(value_fails_neg);
        assert!(zstar_fails__neg.is_err());
    }
    #[test]
    fn randomly_sample_element_in_zkstar_works() {
        let mut rng = init_testing();
        let (_, p, q) = DecryptionKey::new(&mut rng).unwrap();
        let builder = ZStarNBuilder::new(&p * &q);
        let zstar = ZStarN::random_element(&builder, &mut rng);
        assert!(zstar.is_ok());
    }
    #[test]
    fn zkstar_serialization_deserialization_works() {
        let mut rng = init_testing();
        let (_, p, q) = DecryptionKey::new(&mut rng).unwrap();
        let builder = ZStarNBuilder::new(&p * &q);

        let value_verifies = ZStarNUnverified::new((&p - 1) / 2);
        let zstar_verifies: ZStarN = builder.validate(value_verifies).unwrap();

        let ser = serialize!(&zstar_verifies).unwrap();
        let zstar_unverified: ZStarNUnverified = deserialize!(&ser).unwrap();
        let zstart_verifies = builder.validate(zstar_unverified);

        assert!(zstart_verifies.is_ok());
        assert_eq!(zstart_verifies.unwrap().as_bignumber(), &((&p - 1) / 2));
    }
    #[test]
    fn zkstar_rejects_deserialized_elements_outside_group() {
        let mut rng = init_testing();

        let (_, p, q) = DecryptionKey::new(&mut rng).unwrap();
        let builder = ZStarNBuilder::new(&p * &q);

        let zstar_unverified_fail = ZStarNUnverified::new(q);
        let zstart_fails = builder.validate(zstar_unverified_fail);
        assert!(zstart_fails.is_err());
    }
}
