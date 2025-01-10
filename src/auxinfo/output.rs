//! Auxinfo output module enforces correct construction of the type!

use std::collections::HashSet;

use crate::{
    auxinfo::info::{AuxInfoPrivate, AuxInfoPublic},
    errors::{CallerError, InternalError, Result},
    protocol::ParticipantIdentifier,
};
use tracing::error;

#[cfg(test)]
use rand::{CryptoRng, RngCore};
/// Output produced by running the auxinfo protocol.
///
/// This should include an [`AuxInfoPublic`] for every protocol participant
/// and an [`AuxInfoPrivate`] for participant that receives this output.
#[derive(Debug, Clone)]
pub struct Output {
    public_auxinfo: Vec<AuxInfoPublic>,
    private_auxinfo: AuxInfoPrivate,
}

impl Output {
    /// Create a new `Output` from its constituent parts.
    ///
    /// The parts must constitute a valid output:
    /// - the public components should be from a unique set of participants;
    /// - the private component should have a corresponding public component.
    pub fn from_parts(
        public_auxinfo: Vec<AuxInfoPublic>,
        private_auxinfo: AuxInfoPrivate,
    ) -> Result<Self> {
        let pids = public_auxinfo
            .iter()
            .map(AuxInfoPublic::participant)
            .collect::<HashSet<_>>();
        if pids.len() != public_auxinfo.len() {
            error!("Tried to create an auxinfo output using a set of public material from non-unique participants");
            Err(CallerError::BadInput)?
        }

        let expected_public_key = private_auxinfo.encryption_key();
        if !public_auxinfo
            .iter()
            .any(|auxinfo| &expected_public_key == auxinfo.pk())
        {
            error!(
                "Auxinfo private material did not match any of the provided auxinfo public keys"
            );
            Err(CallerError::BadInput)?
        }

        Ok(Self {
            public_auxinfo,
            private_auxinfo,
        })
    }

    /// Decompose the `Output` into its constituent parts.
    ///
    /// # 🔒 Storage requirements
    /// The [`AuxInfoPrivate`] must be stored securely by the calling
    /// application, and a best effort should be made to drop it from memory
    /// after it's securely stored.
    ///
    /// The public components can be stored in the clear.
    pub fn into_parts(self) -> (Vec<AuxInfoPublic>, AuxInfoPrivate) {
        (self.public_auxinfo, self.private_auxinfo)
    }

    pub(crate) fn public_auxinfo(&self) -> &[AuxInfoPublic] {
        &self.public_auxinfo
    }

    pub(crate) fn private_pid(&self) -> Result<ParticipantIdentifier> {
        let expected_public_key = self.private_auxinfo.encryption_key();
        match self
            .public_auxinfo
            .iter()
            .find(|auxinfo| &expected_public_key == auxinfo.pk())
        {
            Some(public_auxinfo) => Ok(public_auxinfo.participant()),
            None => {
                error!("Didn't find public aux info corresponding to the private aux info, but there should be one by construction");
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    pub(crate) fn find_public(&self, pid: ParticipantIdentifier) -> Option<&AuxInfoPublic> {
        self.public_auxinfo
            .iter()
            .find(|public_key| public_key.participant() == pid)
    }

    pub(crate) fn private_auxinfo(&self) -> &AuxInfoPrivate {
        &self.private_auxinfo
    }

    /// Filter the output to only include the auxinfo for the given
    /// participants.
    pub fn filter_participants(&self, pids: &[ParticipantIdentifier]) -> Self {
        let public_auxinfo = self
            .public_auxinfo
            .iter()
            .filter(|auxinfo| pids.contains(&auxinfo.participant()))
            .cloned()
            .collect();

        Self {
            public_auxinfo,
            private_auxinfo: self.private_auxinfo.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        paillier::DecryptionKey, ring_pedersen::VerifiedRingPedersen, utils::testing::init_testing,
        ParticipantConfig,
    };

    impl Output {
        /// Simulate the valid output of an auxinfo run with the given
        /// participants.
        ///
        /// This should __never__ be called outside of tests! The given `pids`
        /// must not contain duplicates.
        pub(crate) fn simulate(
            pids: &[ParticipantIdentifier],
            rng: &mut (impl CryptoRng + RngCore),
        ) -> Self {
            let (mut private_auxinfo, public_auxinfo): (Vec<_>, Vec<_>) = pids
                .iter()
                .map(|&pid| {
                    let (key, _, _) = DecryptionKey::new(rng).unwrap();
                    (
                        AuxInfoPrivate::from(key.clone()),
                        AuxInfoPublic::new(
                            &(),
                            pid,
                            key.encryption_key(),
                            VerifiedRingPedersen::extract(&key, &(), rng).unwrap(),
                        )
                        .unwrap(),
                    )
                })
                .unzip();

            Self::from_parts(public_auxinfo, private_auxinfo.pop().unwrap()).unwrap()
        }

        /// Simulate a consistent, valid output of an auxinfo run with the given
        /// participants.
        ///
        /// This produces output for every config in the provided set. The
        /// config must have a non-zero length and the given `pids` must not
        /// contain duplicates.
        pub(crate) fn simulate_set(
            configs: &[ParticipantConfig],
            rng: &mut (impl CryptoRng + RngCore),
        ) -> Vec<Self> {
            let (public_auxinfo, private_auxinfo): (Vec<_>, Vec<_>) = configs
                .iter()
                .map(|config| {
                    let (key, _, _) = DecryptionKey::new(rng).unwrap();
                    (
                        AuxInfoPublic::new(
                            &(),
                            config.id(),
                            key.encryption_key(),
                            VerifiedRingPedersen::extract(&key, &(), rng).unwrap(),
                        )
                        .unwrap(),
                        AuxInfoPrivate::from(key),
                    )
                })
                .unzip();

            private_auxinfo
                .into_iter()
                .map(|private_auxinfo| {
                    Self::from_parts(public_auxinfo.clone(), private_auxinfo).unwrap()
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

        let (public, private) = output.into_parts();
        assert!(Output::from_parts(public, private).is_ok());
    }

    #[test]
    fn participants_must_be_unique() {
        let rng = &mut init_testing();
        let mut pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        // Duplicate one of the PIDs
        pids.push(pids[4]);

        let (mut private_auxinfo, public_auxinfo): (Vec<_>, Vec<_>) = pids
            .iter()
            .map(|&pid| {
                let (key, _, _) = DecryptionKey::new(rng).unwrap();
                (
                    AuxInfoPrivate::from(key.clone()),
                    AuxInfoPublic::new(
                        &(),
                        pid,
                        key.encryption_key(),
                        VerifiedRingPedersen::extract(&key, &(), rng).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .unzip();

        assert!(Output::from_parts(public_auxinfo, private_auxinfo.pop().unwrap()).is_err());
    }

    #[test]
    fn private_output_must_correspond_to_a_public() {
        let rng = &mut init_testing();
        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();

        // Use the simulate function to get a set of valid public components
        let valid_publics = Output::simulate(&pids, rng).public_auxinfo;

        // Make a random private component
        // If randomness somehow breaks, it's possible that this could correspond to one
        // of the public ones but it's so unlikely that we're not going to try
        // to check that here.
        let bad_private = AuxInfoPrivate::from(DecryptionKey::new(rng).unwrap().0);

        assert!(Output::from_parts(valid_publics, bad_private).is_err());
    }
}
