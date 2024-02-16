//! Wrapper types around commonly used types, e.g. `BigNumber` that should be
//! zeroized after use TODO
use crate::{errors::InternalError, paillier::Nonce};
use k256::elliptic_curve::rand_core::{CryptoRng, RngCore};
use libpaillier::unknown_order::BigNumber;
use rand::Rng;
use std::{
    fmt::{Debug, Formatter},
    ops::{Deref, Neg},
};
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// /// TODO: Keep this zeroondrop here? Or move it down as a bound on T?
// #[derive(Clone)]
// pub(crate) struct Secret<T> {
//     secret: Box<T>,
// }
//
// impl<T: ZeroizeOnDrop> Secret<T> {
//     pub fn from_value(secret: T) -> Self {
//         Self {
//             secret: Box::new(secret),
//         }
//     }
//
//     pub fn from_box(secret: Box<T>) -> Self {
//         Self { secret }
//     }
//
//     /// TODO ... We
//     /// should be careful about cloning the returned reference.
//     pub fn get_secret(&self) -> &T {
//         self.secret.deref()
//     }
// }

#[derive(Eq, PartialEq, Clone, ZeroizeOnDrop)]
pub(crate) struct SecretBigNumber(Box<BigNumber>);

impl Debug for SecretBigNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBigNumber")
            .field("data", &"REDACTED")
            .finish()
    }
}

impl Neg for SecretBigNumber {
    type Output = Self;

    fn neg(self) -> Self::Output {
        SecretBigNumber(Box::new(-self.get_secret()))
    }
}

impl SecretBigNumber {
    // TODO: Get rid of this constructor? Probably. Keeping it in now just
    // for the sake of compiling...
    pub fn from_value(secret: &BigNumber) -> Self {
        Self(Box::new(secret.clone()))
    }

    /// Sample a number uniformly at random from the range [0, n). This can be
    /// used for sampling from a prime field `F_p` or the integers modulo
    /// `n` (for any `n`).
    pub(crate) fn random_positive_bn<R: RngCore + CryptoRng>(
        rng: &mut R,
        n: &BigNumber,
    ) -> SecretBigNumber {
        Self::from_rng(n, rng)
    }

    /// Sample a number uniformly at random from the range `[-2^n, 2^n]`.
    pub(crate) fn random_plusminus_by_size<R: RngCore + CryptoRng>(
        rng: &mut R,
        n: usize,
    ) -> SecretBigNumber {
        let range = BigNumber::one() << n;
        SecretBigNumber::random_plusminus(rng, &range)
    }

    /// Sample a number uniformly at random from the range [-n, n].
    pub(crate) fn random_plusminus<R: RngCore + CryptoRng>(
        rng: &mut R,
        n: &BigNumber,
    ) -> SecretBigNumber {
        // `from_rng()` samples the _open_ interval, so add 1 to get the closed interval
        // for `n`
        let open_interval_max: BigNumber = n + 1;
        let val = Self::from_rng(&open_interval_max, rng);
        let is_positive: bool = rng.gen();
        if is_positive {
            val
        } else {
            -val
        }
    }

    /// [`SecretBigNumber`] equivalent to `from_rng` TODO
    fn from_rng(n: &BigNumber, rng: &mut impl RngCore) -> SecretBigNumber {
        // Note: TODO we don't zeroize the stack allocated value here...
        let bn = BigNumber::from_rng(n, rng);
        SecretBigNumber(Box::new(bn))
    }

    /// Sample a number uniformly at random from the range `[-2^max, -2^min] U
    /// [2^min, 2^max]`.
    #[cfg(test)]
    pub(crate) fn random_plusminus_by_size_with_minimum<R: RngCore + CryptoRng>(
        rng: &mut R,
        max: usize,
        min: usize,
    ) -> crate::errors::Result<SecretBigNumber> {
        if min >= max {
            error!(
                "Can't sample from specified range because lower bound is not smaller
             than upper bound. \nLower bound: {}\nUpper bound: {}",
                min, max
            );
            return Err(InternalError::InternalInvariantFailed);
        }
        // Sample from [0, 2^max - 2^min], then add 2^min to bump into correct range.
        let min_bound_bn = (BigNumber::one() << max) - (BigNumber::one() << min);
        let mut val = BigNumber::from_rng(&min_bound_bn, rng) + (BigNumber::one() << min);
        let secret_val = SecretBigNumber::from_value(&val);
        val.zeroize();

        let is_positive: bool = rng.gen();
        Ok(match is_positive {
            true => secret_val,
            false => -secret_val,
        })
    }

    /// TODO ... should be careful about cloning the returned reference.
    pub fn get_secret(&self) -> &BigNumber {
        self.0.deref()
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub(crate) struct SecretNonce(Nonce);

impl SecretNonce {
    pub fn from_nonce(nonce: Nonce) -> SecretNonce {
        SecretNonce(nonce)
    }

    /// This method gives you access to the underlying secret nonce. We should
    /// be careful about cloning the returned reference.
    pub fn get_nonce_secret(&self) -> &Nonce {
        &self.0
    }
}

// #[derive(Clone, ZeroizeOnDrop, Debug)]
// pub(crate) struct SecretScalar(Scalar);
//
// impl SecretScalar {
//     pub fn from_scalar(scalar: Scalar) -> SecretScalar {
//         SecretScalar(scalar)
//     }
//
//     pub fn invert(&self) -> CtOption<SecretScalar> {
//         self.get_secret().invert().map(SecretScalar)
//     }
//
//     /// This method gives you access to the underlying secret scalar. We
// should     /// be careful about cloning the returned reference.
//     pub fn get_secret(&self) -> &Scalar {
//         &self.0
//     }
// }
//
// impl AddAssign<&SecretScalar> for SecretScalar {
//     fn add_assign(&mut self, other: &SecretScalar) {
//         self.0 += &other.0;
//     }
// }
