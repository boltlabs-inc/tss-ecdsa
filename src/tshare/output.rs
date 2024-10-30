// Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use k256::Scalar;
use std::collections::HashSet;

use crate::{
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePublic,
    utils::CurvePoint,
};

use k256::ecdsa::VerifyingKey;
use tracing::error;

use super::CoeffPublic;

/// Output type from key generation, including all parties' public key shares,
/// this party's private key share, and the public coefficients from the
/// subjacent Lagrange interpolation.
#[derive(Debug, Clone)]
pub struct Output {
    // Public coefficients for the polynomial
    public_coeffs: Vec<CoeffPublic>,
    // Public keys for each participant
    public_key_shares: Vec<KeySharePublic>,
    // A Scalar representing the private share,
    private_key_share: Scalar,
    // The chain code for the HD wallet
    chain_code: [u8; 32],
    // The chain code for the HD wallet
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

    /// Get the public coefficients (coefficients in the exponent).
    pub fn public_coeffs(&self) -> &[CoeffPublic] {
        &self.public_coeffs
    }

    /// Get the private share
    pub fn private_key_share(&self) -> &Scalar {
        &self.private_key_share
    }

    /// Get the chaincode.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the rid.
    pub fn rid(&self) -> &[u8; 32] {
        &self.rid
    }

    /// Create a new `Output` from its constitutent parts.
    ///
    /// This method should only be used with components that were previously
    /// derived via the [`Output::into_parts()`] method; the calling application
    /// should not try to form public and private key shares independently.
    ///
    /// The provided components must satisfy the following properties:
    /// - Validity of private key share can be checked using Feldman's VSS.
    /// - The public key shares must be from a unique set of participants.
    pub fn from_parts(
        public_coeffs: Vec<CoeffPublic>,
        public_keys: Vec<KeySharePublic>,
        private_key_share: Scalar,
        chain_code: [u8; 32],
        rid: [u8; 32],
    ) -> Result<Self> {
        let pids = public_keys
            .iter()
            .map(KeySharePublic::participant)
            .collect::<HashSet<_>>();
        if pids.len() != public_keys.len() {
            error!("Tried to create a keygen output using a set of public material from non-unique participants");
            Err(CallerError::BadInput)?
        }
        if pids.len() < public_coeffs.len() {
            error!("Not enough participants to support the given polynomial");
            Err(CallerError::BadInput)?
        }

        Ok(Self {
            public_coeffs,
            public_key_shares: public_keys,
            private_key_share,
            chain_code,
            rid,
        })
    }

    /// Decompose the `Output` into its constituent parts.
    ///
    /// # 🔒 Storage requirements
    /// The private_key_share must be stored securely by the calling
    /// application, and a best effort should be made to drop it from memory
    /// after it's securely stored.
    ///
    /// The public components (including the byte array and the public key
    /// shares) can be stored in the clear.
    pub fn into_parts(
        self,
    ) -> (
        Vec<CoeffPublic>,
        Vec<KeySharePublic>,
        Scalar,
        [u8; 32],
        [u8; 32],
    ) {
        (
            self.public_coeffs,
            self.public_key_shares,
            self.private_key_share,
            self.chain_code,
            self.rid,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tshare::{CoeffPrivate, CoeffPublic, TshareParticipant},
        utils::{bn_to_scalar, k256_order, testing::init_testing},
        ParticipantIdentifier,
    };
    use itertools::Itertools;
    use k256::elliptic_curve::Field;
    use libpaillier::unknown_order::BigNumber;
    use rand::Rng;

    impl Output {
        /// Simulate the valid output of a keygen run with the given
        /// participants.
        ///
        /// This should __never__ be called outside of tests! The given `pids`
        /// must not contain duplicates. Self is the last participant in `pids`.
        pub(crate) fn simulate(pids: &[ParticipantIdentifier]) -> Self {
            let (private_key_shares, public_key_shares): (Vec<_>, Vec<_>) = pids
                .iter()
                .map(|&pid| {
                    // TODO #340: Replace with KeyShare methods once they exist.
                    let secret = BigNumber::random(&k256_order());
                    let public = CurvePoint::GENERATOR
                        .multiply_by_bignum(&secret)
                        .expect("can't multiply by generator");
                    (secret, KeySharePublic::new(pid, public))
                })
                .unzip();

            let rng = &mut init_testing();
            let chain_code = rng.gen();
            let rid = rng.gen();

            // simulate a random evaluation
            let converted_publics = public_key_shares
                .iter()
                .map(|x| CoeffPublic::new(*x.as_ref()))
                .collect::<Vec<_>>();
            let converted_privates = private_key_shares
                .iter()
                .map(|x| CoeffPrivate {
                    x: bn_to_scalar(x).unwrap(),
                })
                .collect::<Vec<_>>();
            let eval_public_at_first_pid =
                TshareParticipant::eval_public_share(converted_publics.as_slice(), pids[0])
                    .unwrap();
            let eval_private_at_first_pid =
                TshareParticipant::eval_private_share(converted_privates.as_slice(), pids[0]);
            let output = Self::from_parts(
                converted_publics,
                public_key_shares,
                eval_private_at_first_pid.x,
                chain_code,
                rid,
            )
            .unwrap();

            let implied_public = eval_private_at_first_pid.public_point();
            assert!(implied_public == eval_public_at_first_pid);
            output
        }
    }

    #[test]
    fn from_into_parts_works() {
        let rng = &mut init_testing();
        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let output = Output::simulate(&pids);

        let (public_coeffs, public_keys, private_key, chain_code, rid) = output.into_parts();
        assert!(
            Output::from_parts(public_coeffs, public_keys, private_key, chain_code, rid).is_ok()
        );
    }

    #[test]
    fn public_shares_must_not_have_duplicate_pids() {
        let mut rng = &mut init_testing();
        let mut pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();

        // Duplicate one of the PIDs
        pids.push(pids[4]);

        // Form output with the duplicated PID
        let (mut private_key_shares, public_key_shares, public_coeffs): (Vec<_>, Vec<_>, Vec<_>) =
            pids.iter()
                .map(|&pid| {
                    // TODO #340: Replace with KeyShare methods once they exist.
                    let secret = Scalar::random(&mut rng);
                    let public = CurvePoint::GENERATOR.multiply_by_scalar(&secret);
                    (
                        secret,
                        KeySharePublic::new(pid, public),
                        CoeffPublic::new(public),
                    )
                })
                .multiunzip();

        let rng = &mut init_testing();
        let chain_code = rng.gen();
        let rid = rng.gen();

        assert!(Output::from_parts(
            public_coeffs,
            public_key_shares,
            private_key_shares.pop().unwrap(),
            chain_code,
            rid,
        )
        .is_err());
    }
}
