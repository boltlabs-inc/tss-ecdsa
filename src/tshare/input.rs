// Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.
use std::collections::HashSet;

use tracing::error;

use crate::{
    auxinfo::{self, AuxInfoPrivate, AuxInfoPublic},
    errors::{CallerError, InternalError, Result},
    ParticipantConfig, ParticipantIdentifier,
};

use super::share::CoeffPrivate;

/// Input needed for a
/// [`TshareParticipant`](crate::tshare::TshareParticipant) to run.
#[derive(Debug, Clone)]
pub struct Input {
    /// How many parties are needed to sign.
    threshold: usize,
    /// An additive share to turn into Shamir sharing.
    /// Or None to generate a random share.
    share: Option<CoeffPrivate>,
    /// The auxiliary info to encrypt/decrypt messages with other participants.
    auxinfo_output: auxinfo::Output,
}

impl Input {
    /// Creates a new [`Input`] from the outputs of the
    /// [`auxinfo`](crate::auxinfo::AuxInfoParticipant) and
    /// [`keygen`](crate::keygen::KeygenParticipant) protocols.
    pub fn new(auxinfo_output: auxinfo::Output, threshold: usize) -> Result<Self> {
        // The constructor for auxinfo output already check other important
        // properties, like that the private component maps to one of public
        // components for each one.
        Ok(Self {
            auxinfo_output,
            share: None,
            threshold,
        })
    }

    pub fn share(&self) -> Option<&CoeffPrivate> {
        self.share.as_ref()
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    fn auxinfo_pids(&self) -> HashSet<ParticipantIdentifier> {
        self.auxinfo_output
            .public_auxinfo()
            .iter()
            .map(AuxInfoPublic::participant)
            .collect()
    }

    // Check the consistency of participant IDs.
    pub(crate) fn check_participant_config(&self, config: &ParticipantConfig) -> Result<()> {
        let config_pids = config
            .all_participants()
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        if config_pids != self.auxinfo_pids() {
            error!("Public auxinfo and participant inputs weren't from the same set of parties.");
            Err(CallerError::BadInput)?
        }

        if config.id() != self.auxinfo_output.private_pid()? {
            error!("Expected private auxinfo output and tshare input to correspond to the same participant, but they didn't");
            Err(CallerError::BadInput)?
        }

        Ok(())
    }

    pub(crate) fn private_auxinfo(&self) -> &AuxInfoPrivate {
        self.auxinfo_output.private_auxinfo()
    }

    /// Returns the [`AuxInfoPublic`] associated with the given
    /// [`ParticipantIdentifier`].
    pub(crate) fn find_auxinfo_public(&self, pid: ParticipantIdentifier) -> Result<&AuxInfoPublic> {
        self.auxinfo_output.find_public(pid)
            .ok_or_else(|| {
                error!("Presign input doesn't contain a public auxinfo for {}, even though we checked for it at construction.", pid);
                InternalError::InternalInvariantFailed
            })
    }
}

#[cfg(test)]
mod test {
    use super::{super::TshareParticipant, Input};
    use crate::{
        auxinfo,
        errors::{CallerError, InternalError, Result},
        keygen,
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ProtocolParticipant,
    };

    #[test]
    fn protocol_participants_must_match_input_participants() -> Result<()> {
        let rng = &mut init_testing();
        let SIZE = 5;

        // Create valid input set with random PIDs
        let config = ParticipantConfig::random(5, rng);
        let auxinfo_output = auxinfo::Output::simulate(&config.all_participants(), rng);
        let input = Input::new(auxinfo_output, 2)?;

        // Create valid config with PIDs independent of those used to make the input set
        let config = ParticipantConfig::random(SIZE, rng);

        let result = TshareParticipant::new(
            Identifier::random(rng),
            config.id(),
            config.other_ids().to_vec(),
            input,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );

        Ok(())
    }

    // TODO: tests for other invalid inputs.
}
