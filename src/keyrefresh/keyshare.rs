// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    keygen::{KeySharePrivate, KeySharePublic},
    paillier::{Ciphertext, DecryptionKey, EncryptionKey},
    ParticipantIdentifier,
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, marker::PhantomData};
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encrypted [`KeyUpdatePrivate`].
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyUpdateEncrypted<C: CurveTrait> {
    ciphertext: Ciphertext,
    phantom: PhantomData<C>,
}

impl<C: CurveTrait> KeyUpdateEncrypted<C> {
    pub fn encrypt<R: RngCore + CryptoRng>(
        update: &KeyUpdatePrivate<C>,
        pk: &EncryptionKey,
        rng: &mut R,
    ) -> Result<Self> {
        if &(C::order() * 2) >= pk.modulus() {
            error!("KeyUpdateEncrypted encryption failed, pk.modulus() is too small");
            Err(InternalError::InternalInvariantFailed)?;
        }

        let (ciphertext, _nonce) = pk
            .encrypt(rng, &update.x)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        Ok(KeyUpdateEncrypted::<C> {
            ciphertext,
            phantom: PhantomData,
        })
    }

    pub fn decrypt(&self, dk: &DecryptionKey) -> Result<KeyUpdatePrivate<C>> {
        let x = dk.decrypt(&self.ciphertext).map_err(|_| {
            error!("KeyUpdateEncrypted decryption failed, ciphertext out of range",);
            CallerError::DeserializationFailed
        })?;
        if x >= C::order() || x < BigNumber::one() {
            error!("KeyUpdateEncrypted decryption failed, plaintext out of range");
            Err(CallerError::DeserializationFailed)?;
        }
        Ok(KeyUpdatePrivate {
            x,
            phantom: PhantomData,
        })
    }
}

/// Private update corresponding to a given
/// [`Participant`](crate::Participant)'s.
#[derive(Clone, ZeroizeOnDrop, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUpdatePrivate<C> {
    x: BigNumber, // in the range [1, q)
    phantom: PhantomData<C>,
}

impl<C> Debug for KeyUpdatePrivate<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyUpdatePrivate([redacted])")
    }
}

impl<C: CurveTrait> KeyUpdatePrivate<C> {
    /// Sample a private key share uniformly at random.
    pub(crate) fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let random_bn = BigNumber::from_rng(&C::order(), rng);
        KeyUpdatePrivate {
            x: random_bn,
            phantom: PhantomData,
        }
    }

    /// Compute a private key share such that the sum of all shares equals 0 mod
    /// q.
    pub(crate) fn zero_sum(others: &[Self]) -> Self {
        let sum = others
            .iter()
            .fold(BigNumber::zero(), |sum, o| sum + o.x.clone());
        let balance = (-sum).nmod(&C::order());
        KeyUpdatePrivate {
            x: balance,
            phantom: PhantomData,
        }
    }

    pub(crate) fn sum(shares: &[Self]) -> Self {
        let sum = shares
            .iter()
            .fold(BigNumber::zero(), |sum, o| sum + o.x.clone())
            .nmod(&C::order());
        KeyUpdatePrivate {
            x: sum,
            phantom: PhantomData,
        }
    }

    pub(crate) fn apply(self, current_sk: &KeySharePrivate<C>) -> KeySharePrivate<C> {
        let mut sum = current_sk.as_ref() + &self.x;
        let share = KeySharePrivate::from_bigint(&sum);
        sum.zeroize();
        share
    }

    /// Computes the "raw" curve point corresponding to this private key.
    pub(crate) fn public_point(&self) -> Result<C> {
        C::scale_generator(&self.x)
    }
}

impl<C> AsRef<BigNumber> for KeyUpdatePrivate<C> {
    /// Get the private key share.
    fn as_ref(&self) -> &BigNumber {
        &self.x
    }
}

/// A curve point representing a given [`Participant`](crate::Participant)'s
/// public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyUpdatePublic<C> {
    participant: ParticipantIdentifier,
    X: C,
}

impl<C: CurveTrait> KeyUpdatePublic<C> {
    pub(crate) fn new(participant: ParticipantIdentifier, share: C) -> Self {
        Self {
            participant,
            X: share,
        }
    }

    /// Get the ID of the participant who claims to hold the private share
    /// corresponding to this public key share.
    pub fn participant(&self) -> ParticipantIdentifier {
        self.participant
    }

    /// Generate a new [`KeySharePrivate`] and [`KeySharePublic`].
    pub(crate) fn new_keyshare<R: RngCore + CryptoRng>(
        participant: ParticipantIdentifier,
        rng: &mut R,
    ) -> Result<(KeyUpdatePrivate<C>, KeyUpdatePublic<C>)> {
        let private_share = KeyUpdatePrivate::<C>::random(rng);
        let public_share = private_share.public_point()?;

        Ok((
            private_share,
            KeyUpdatePublic::new(participant, public_share),
        ))
    }

    pub(crate) fn sum(participant: ParticipantIdentifier, shares: &[Self]) -> Self {
        let sum = shares.iter().fold(C::IDENTITY, |sum, o| sum + o.X);
        Self {
            participant,
            X: sum,
        }
    }

    pub(crate) fn apply(&self, current_pk: &KeySharePublic<C>) -> KeySharePublic<C> {
        let sum = *current_pk.as_ref() + self.X;
        KeySharePublic::new(current_pk.participant(), sum)
    }
}

impl<C> AsRef<C> for KeyUpdatePublic<C> {
    /// Get the public curvepoint which is the public key share.
    fn as_ref(&self) -> &C {
        &self.X
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{auxinfo, curve::TestCurve as C, keyrefresh, utils::testing::init_testing};
    use rand::rngs::StdRng;

    /// Generate an encryption key pair.
    fn setup() -> (StdRng, EncryptionKey, DecryptionKey) {
        let mut rng = init_testing();
        let pid = ParticipantIdentifier::random(&mut rng);
        let auxinfo = auxinfo::Output::simulate(&[pid], &mut rng);
        let dk = auxinfo.private_auxinfo().decryption_key();
        let pk = auxinfo.find_public(pid).unwrap().pk();
        assert!(
            &(C::order() * 2) < pk.modulus(),
            "the Paillier modulus is supposed to be much larger than the k256 order"
        );
        (rng, pk.clone(), dk.clone())
    }

    #[test]
    fn key_update_encryption_works() {
        let (mut rng, pk, dk) = setup();
        let rng = &mut rng;

        // Encryption round-trip.
        let share: keyrefresh::keyshare::KeyUpdatePrivate<C> = KeyUpdatePrivate::random(rng);
        let encrypted = KeyUpdateEncrypted::encrypt(&share, &pk, rng).expect("encryption failed");
        let decrypted = encrypted.decrypt(&dk).expect("decryption failed");

        assert_eq!(decrypted, share);
    }

    #[test]
    fn key_update_decrypt_out_of_range() {
        let (mut rng, pk, dk) = setup();
        let rng = &mut rng;

        // Encrypt invalid shares.
        for x in [BigNumber::zero(), -BigNumber::one(), C::order()].iter() {
            let share: keyrefresh::keyshare::KeyUpdatePrivate<C> = KeyUpdatePrivate {
                x: x.clone(),
                phantom: PhantomData,
            };
            let encrypted =
                KeyUpdateEncrypted::encrypt(&share, &pk, rng).expect("encryption failed");
            // Decryption reports an error.
            let decrypt_result = encrypted.decrypt(&dk);
            assert!(decrypt_result.is_err());
        }
    }

    #[test]
    fn key_update_private_zero_sum_works() {
        // Random shares do not sum to zero.
        let rng = &mut init_testing();
        let mut shares = (0..5)
            .map(|_| KeyUpdatePrivate::<C>::random(rng))
            .collect::<Vec<_>>();
        assert_ne!(KeyUpdatePrivate::sum(&shares).x, BigNumber::zero());

        // Balance the sum to zero.
        let balance_share = KeyUpdatePrivate::zero_sum(&shares);
        assert_ne!(balance_share.x, BigNumber::zero());
        shares.push(balance_share);

        // Check that the sum is zero now.
        assert_eq!(KeyUpdatePrivate::sum(&shares).x, BigNumber::zero());
    }
}
