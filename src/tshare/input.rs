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
    pub fn new(
        auxinfo_output: auxinfo::Output,
        share: Option<CoeffPrivate>,
        threshold: usize,
    ) -> Result<Self> {
        // The constructor for auxinfo output already check other important
        // properties, like that the private component maps to one of public
        // components for each one.
        Ok(Self {
            auxinfo_output,
            share,
            threshold,
        })
    }

    /// Returns the share to be used in the protocol.
    pub fn share(&self) -> Option<&CoeffPrivate> {
        self.share.as_ref()
    }

    /// Returns the threshold for the protocol.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the participant IDs associated with the auxinfo output.
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
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ParticipantIdentifier, ProtocolParticipant,
    };

    #[test]
    fn protocol_participants_must_match_input_participants() -> Result<()> {
        let rng = &mut init_testing();
        let SIZE = 5;

        // Create valid input set with random PIDs
        let config = ParticipantConfig::random(SIZE, rng);
        let auxinfo_output = auxinfo::Output::simulate(&config.all_participants(), rng);
        let input = Input::new(auxinfo_output, None, 2)?;

        // Create valid config with PIDs independent of those used to make the input set
        let independent_config = ParticipantConfig::random(SIZE, rng);

        let result = TshareParticipant::new(
            Identifier::random(rng),
            independent_config.id(),
            independent_config.other_ids().to_vec(),
            input,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );

        Ok(())
    }

    #[test]
    fn auxinfo_must_match_input_participants() -> Result<()> {
        let rng = &mut init_testing();
        let SIZE = 5;

        // Create valid input set with random PIDs
        let config = ParticipantConfig::random(SIZE, rng);

        // Create valid config with PIDs independent of those used to make the input set
        let independent_config = ParticipantConfig::random(SIZE, rng);

        // Replace auxinfo_output with a new one that doesn't match the config
        let auxinfo_output = auxinfo::Output::simulate(&independent_config.all_participants(), rng);
        let input_with_invalid_auxinfo = Input::new(auxinfo_output, None, 2)?;
        let result = TshareParticipant::new(
            Identifier::random(rng),
            config.id(),
            config.other_ids().to_vec(),
            input_with_invalid_auxinfo,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );

        Ok(())
    }

    #[test]
    fn auxinfo_id_must_match_input_participants() -> Result<()> {
        let rng = &mut init_testing();
        let SIZE = 5;

        // create quorum
        let quorum = ParticipantConfig::random_quorum(SIZE, rng).unwrap();

        // Replace auxinfo_output with a new one that doesn't match the config
        let auxinfo_output = auxinfo::Output::simulate(&quorum[0].all_participants(), rng);
        let input_auxinfo = Input::new(auxinfo_output, None, 2)?;
        let result = TshareParticipant::new(
            Identifier::random(rng),
            quorum[1].id(),
            quorum[1].other_ids().to_vec(),
            input_auxinfo,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );

        Ok(())
    }

    #[test]
    fn find_existing_auxinfo_public() -> Result<()> {
        let rng = &mut init_testing();
        let SIZE = 5;

        // Create valid input set with random PIDs
        let config = ParticipantConfig::random(SIZE, rng);
        let auxinfo_output = auxinfo::Output::simulate(&config.all_participants(), rng);
        let input = Input::new(auxinfo_output, None, 2)?;

        let pid = config.all_participants()[0];
        let auxinfo_public = input.find_auxinfo_public(pid)?;
        assert_eq!(auxinfo_public.participant(), pid);

        Ok(())
    }

    #[test]
    fn find_non_existing_auxinfo_public_should_fail() -> Result<()> {
        let rng = &mut init_testing();
        let SIZE = 5;

        // Create valid input set with random PIDs
        let config = ParticipantConfig::random(SIZE, rng);
        let auxinfo_output = auxinfo::Output::simulate(&config.all_participants(), rng);
        let input = Input::new(auxinfo_output, None, 2)?;

        let pid = ParticipantIdentifier::random(rng);
        let result = input.find_auxinfo_public(pid);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), InternalError::InternalInvariantFailed);

        Ok(())
    }
}
