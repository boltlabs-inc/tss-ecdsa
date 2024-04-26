// Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::collections::HashSet;

use crate::{
    errors::{CallerError, InternalError, Result},
    keygen::keyshare::{KeySharePrivate, KeySharePublic},
    utils::CurvePoint,
    ParticipantIdentifier,
};

use k256::ecdsa::VerifyingKey;
use tracing::error;

/// Output type from key generation, including all parties' public key shares,
/// this party's private key share, and a bit of global randomness.
#[derive(Debug, Clone)]
pub struct Output {
    public_key_shares: Vec<KeySharePublic>,
    private_key_share: KeySharePrivate,
    rid: [u8; 32],
}

impl Output {
    /// Construct the generated public key.
    pub fn public_key(&self) -> Result<VerifyingKey> {
        // Add up all the key shares
        let public_key_point = self
            .public_key_shares
            .iter()
            .fold(CurvePoint::IDENTITY, |sum, share| sum + *share.as_ref());

        VerifyingKey::from_encoded_point(&public_key_point.into()).map_err(|_| {
            error!("Keygen output does not produce a valid public key.");
            InternalError::InternalInvariantFailed
        })
    }

    /// Get the individual shares of the public key.
    pub fn public_key_shares(&self) -> &[KeySharePublic] {
        &self.public_key_shares
    }

    pub(crate) fn private_key_share(&self) -> &KeySharePrivate {
        &self.private_key_share
    }

    /// Get the [`ParticipantIdentifier`] corresponding to the
    /// [`KeySharePrivate`].
    pub(crate) fn private_pid(&self) -> Result<ParticipantIdentifier> {
        let expected_public_share = self.private_key_share.public_share()?;
        match self
            .public_key_shares
            .iter()
            .find(|share| share.as_ref() == &expected_public_share)
        {
            Some(public_key_share) => Ok(public_key_share.participant()),
            None => {
                error!("Didn't find a public key share corresponding to the private key share, but there should be one by construction");
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    /// Get the shared randomness generated during key generation.
    pub(crate) fn rid(&self) -> &[u8; 32] {
        &self.rid
    }

    /// Create a new `Output` from its constitutent parts.
    ///
    /// This method should only be used with components that were previously
    /// derived via the [`Output::into_parts()`] method; the calling application
    /// should not try to form public and private key shares independently.
    ///
    /// The provided components must satisfy the following properties:
    /// - There is a valid key pair -- that is, the public key corresponding to
    ///   the private key share must be contained in the list of public shares.
    /// - The public key shares must be from a unique set of participants
    pub fn from_parts(
        public_key_shares: Vec<KeySharePublic>,
        private_key_share: KeySharePrivate,
        rid: [u8; 32],
    ) -> Result<Self> {
        let pids = public_key_shares
            .iter()
            .map(KeySharePublic::participant)
            .collect::<HashSet<_>>();
        if pids.len() != public_key_shares.len() {
            error!("Tried to create a keygen output using a set of public material from non-unique participants");
            Err(CallerError::BadInput)?
        }

        let expected_public_share = private_key_share.public_share()?;
        if !public_key_shares
            .iter()
            .any(|share| share.as_ref() == &expected_public_share)
        {
            error!("Tried to create a keygen output using a private share with no corresponding public share");
            Err(CallerError::BadInput)?
        }

        Ok(Self {
            public_key_shares,
            private_key_share,
            rid,
        })
    }

    /// Decompose the `Output` into its constituent parts.
    ///
    /// # 🔒 Storage requirements
    /// The [`KeySharePrivate`] must be stored securely by the calling
    /// application, and a best effort should be made to drop it from memory
    /// after it's securely stored.
    ///
    /// The public components (including the byte array and the public key
    /// shares) can be stored in the clear.
    pub fn into_parts(self) -> (Vec<KeySharePublic>, KeySharePrivate, [u8; 32]) {
        (self.public_key_shares, self.private_key_share, self.rid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utils::testing::init_testing, ParticipantConfig, ParticipantIdentifier};
    use rand::{CryptoRng, Rng, RngCore};

    impl Output {
        /// Simulate the valid output of a keygen run with the given
        /// participants.
        ///
        /// This should __never__ be called outside of tests! The given `pids`
        /// must not contain duplicates. Self is the last participant in `pids`.
        pub(crate) fn simulate(
            pids: &[ParticipantIdentifier],
            rng: &mut (impl CryptoRng + RngCore),
        ) -> Self {
            let (mut private_key_shares, public_key_shares): (Vec<_>, Vec<_>) = pids
                .iter()
                .map(|&pid| {
                    // TODO #340: Replace with KeyShare methods once they exist.
                    let secret = KeySharePrivate::random(rng);
                    let public = secret.public_share().unwrap();
                    (secret, KeySharePublic::new(pid, public))
                })
                .unzip();

            let rid = rng.gen();

            Self::from_parts(public_key_shares, private_key_shares.pop().unwrap(), rid).unwrap()
        }

        /// Simulate a consistent, valid output of a keygen run with the given
        /// participants.
        ///
        /// This produces output for every config in the provided set. The
        /// config must have a non-zero length, and the given `pids` must not
        /// contain duplicates.
        pub(crate) fn simulate_set(
            configs: &[ParticipantConfig],
            rng: &mut (impl CryptoRng + RngCore),
        ) -> Vec<Self> {
            let (private_key_shares, public_key_shares): (Vec<_>, Vec<_>) = configs
                .iter()
                .map(|config| {
                    // TODO #340: Replace with KeyShare methods once they exist.
                    let secret = KeySharePrivate::random(rng);
                    let public = secret.public_share().unwrap();
                    (secret, KeySharePublic::new(config.id(), public))
                })
                .unzip();

            let rid = rng.gen();

            private_key_shares
                .into_iter()
                .map(|private_key_share| {
                    Self::from_parts(public_key_shares.clone(), private_key_share, rid).unwrap()
                })
                .collect()
        }
    }

    #[test]
    fn from_into_parts_works() {
        let rng = &mut init_testing();
        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let output = Output::simulate(&pids, rng);

        let (public, private, rid) = output.into_parts();
        assert!(Output::from_parts(public, private, rid).is_ok());
    }

    #[test]
    fn private_field_must_correspond_to_a_public() {
        let rng = &mut init_testing();
        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();

        // Use the simulate function to get a set of valid public components
        let output = Output::simulate(&pids, rng);

        // Create a random private share. It's legally possible for this to match one of
        // the public keys but it's so unlikely that we won't check it.
        let bad_private_key_share = KeySharePrivate::random(rng);

        assert!(
            Output::from_parts(output.public_key_shares, bad_private_key_share, output.rid)
                .is_err()
        )
    }

    #[test]
    fn public_shares_must_not_have_duplicate_pids() {
        let rng = &mut init_testing();
        let mut pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();

        // Duplicate one of the PIDs
        pids.push(pids[4]);

        // Form output with the duplicated PID
        let (mut private_key_shares, public_key_shares): (Vec<_>, Vec<_>) = pids
            .iter()
            .map(|&pid| {
                // TODO #340: Replace with KeyShare methods once they exist.
                let secret = KeySharePrivate::random(rng);
                let public = secret.public_share().unwrap();
                (secret, KeySharePublic::new(pid, public))
            })
            .unzip();

        let rid = rng.gen();

        assert!(
            Output::from_parts(public_key_shares, private_key_shares.pop().unwrap(), rid).is_err()
        );
    }
}
