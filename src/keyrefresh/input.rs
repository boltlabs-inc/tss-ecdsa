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
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    keygen::{self, KeySharePrivate, KeySharePublic},
    ParticipantConfig, ParticipantIdentifier,
};

/// Input needed for a
/// [`KeyrefreshParticipant`](crate::keyrefresh::KeyrefreshParticipant) to run.
#[derive(Debug, Clone)]
pub struct Input<C: CurveTrait> {
    /// The key share material for the key that will be refreshed.
    keygen_output: keygen::Output<C>,
    /// The auxiliary info to encrypt/decrypt messages with other participants.
    auxinfo_output: auxinfo::Output,
}

impl<C: CurveTrait> Input<C> {
    /// Creates a new [`Input`] from the outputs of the
    /// [`auxinfo`](crate::auxinfo::AuxInfoParticipant) and
    /// [`keygen`](crate::keygen::KeygenParticipant) protocols.
    pub fn new(auxinfo_output: auxinfo::Output, keygen_output: keygen::Output<C>) -> Result<Self> {
        // The constructors for keygen and auxinfo output already check other important
        // properties, like that the private component maps to one of public
        // components for each one.

        // The participant IDs for the private components of each output should match
        if keygen_output.private_pid() != auxinfo_output.private_pid() {
            error!("Expected private keygen and auxinfo outputs to correspond to the same participant, but they didn't");
            Err(CallerError::BadInput)?
        }

        let input = Self {
            auxinfo_output,
            keygen_output,
        };

        // The same set of participants must have produced the key shares and aux infos.
        if input.auxinfo_pids() != input.keygen_pids() {
            error!("Public auxinfo and keyshare inputs to presign weren't from the same set of parties.");
            Err(CallerError::BadInput)?
        }

        Ok(input)
    }

    pub fn keygen_output(&self) -> &keygen::Output<C> {
        &self.keygen_output
    }

    fn auxinfo_pids(&self) -> HashSet<ParticipantIdentifier> {
        self.auxinfo_output
            .public_auxinfo()
            .iter()
            .map(AuxInfoPublic::participant)
            .collect()
    }

    fn keygen_pids(&self) -> HashSet<ParticipantIdentifier> {
        self.keygen_output
            .public_key_shares()
            .iter()
            .map(KeySharePublic::participant)
            .collect()
    }

    // Check the consistency of participant IDs.
    pub(crate) fn check_participant_config(&self, config: &ParticipantConfig) -> Result<()> {
        let config_pids = config
            .all_participants()
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        if config_pids != self.keygen_pids() {
            error!("Public auxinfo and participant inputs weren't from the same set of parties.");
            Err(CallerError::BadInput)?
        }

        if config.id() != self.keygen_output.private_pid()? {
            error!("Expected private keygen output and keyrefresh input to correspond to the same participant, but they didn't");
            Err(CallerError::BadInput)?
        }

        Ok(())
    }

    pub(crate) fn public_key_shares(&self) -> &[KeySharePublic<C>] {
        self.keygen_output.public_key_shares()
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

    pub(crate) fn private_key_share(&self) -> &KeySharePrivate<C> {
        self.keygen_output.private_key_share()
    }
}

#[cfg(test)]
mod test {
    use super::Input;
    use crate::{
        auxinfo,
        curve::TestCurve,
        errors::{CallerError, InternalError, Result},
        keygen,
        keyrefresh::KeyrefreshParticipant,
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ParticipantIdentifier, ProtocolParticipant,
    };

    #[test]
    fn inputs_must_be_same_length() {
        let rng = &mut init_testing();

        let config = ParticipantConfig::random(5, rng);
        let pids = config.all_participants();
        assert_eq!(pids.last().unwrap(), &config.id());
        let keygen_output: keygen::output::Output<TestCurve> = keygen::Output::simulate(&pids, rng);
        let auxinfo_output = auxinfo::Output::simulate(&pids, rng);

        // Same length works
        let result = Input::new(auxinfo_output.clone(), keygen_output.clone());
        assert!(result.is_ok());

        // If keygen is too short, it fails.
        let short_keygen: keygen::output::Output<TestCurve> =
            keygen::Output::simulate(&pids[1..], rng);
        let result = Input::new(auxinfo_output, short_keygen);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );

        // If auxinfo is too short, it fails.
        let short_auxinfo = auxinfo::Output::simulate(&pids[1..], rng);
        let result = Input::new(short_auxinfo, keygen_output);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );
    }

    #[test]
    fn inputs_must_have_same_participant_sets() {
        let rng = &mut init_testing();

        let config = ParticipantConfig::random(5, rng);
        let auxinfo_output = auxinfo::Output::simulate(&config.all_participants(), rng);

        // Use different pids by mistake.
        let keygen_pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let keygen_output: keygen::output::Output<TestCurve> =
            keygen::Output::simulate(&keygen_pids, rng);

        let result = Input::new(auxinfo_output, keygen_output);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            InternalError::CallingApplicationMistake(CallerError::BadInput)
        );
    }

    #[test]
    fn protocol_participants_must_match_input_participants() -> Result<()> {
        let rng = &mut init_testing();
        let SIZE = 5;

        // Create valid input set with random PIDs
        let config = ParticipantConfig::random(5, rng);
        let keygen_output: keygen::output::Output<TestCurve> =
            keygen::Output::simulate(&config.all_participants(), rng);
        let auxinfo_output = auxinfo::Output::simulate(&config.all_participants(), rng);
        let input = Input::new(auxinfo_output, keygen_output)?;

        // Create valid config with PIDs independent of those used to make the input set
        let config = ParticipantConfig::random(SIZE, rng);

        let result = KeyrefreshParticipant::new(
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
}
