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
    ParticipantIdentifier,
};

/// Input needed for a
/// [`PresignParticipant`](crate::presign::PresignParticipant) to run.
#[derive(Debug, Clone)]
pub struct Input<C> {
    /// The key share material for the key that will be used in the presign run.
    keygen_output: keygen::Output<C>,
    /// The auxiliary info for the key that will be used in the presign run.
    auxinfo_output: auxinfo::Output,
}

impl<C: CurveTrait> Input<C> {
    /// Creates a new [`Input`] from the outputs of the
    /// [`auxinfo`](crate::auxinfo::AuxInfoParticipant) and
    /// [`keygen`](crate::keygen::KeygenParticipant) protocols.
    pub fn new(auxinfo_output: auxinfo::Output, keygen_output: keygen::Output<C>) -> Result<Self> {
        if auxinfo_output.public_auxinfo().len() != keygen_output.public_key_shares().len() {
            error!(
                "Number of auxinfo ({:?}) and keyshare ({:?}) public entries is not equal",
                auxinfo_output.public_auxinfo().len(),
                keygen_output.public_key_shares().len()
            );
            Err(CallerError::BadInput)?
        }

        // The same set of participants must have produced the key shares and aux infos.
        let aux_pids = auxinfo_output
            .public_auxinfo()
            .iter()
            .map(AuxInfoPublic::participant)
            .collect::<HashSet<_>>();
        let key_pids = keygen_output
            .public_key_shares()
            .iter()
            .map(KeySharePublic::<C>::participant)
            .collect::<HashSet<_>>();
        if aux_pids != key_pids {
            error!("Public auxinfo and keyshare inputs to presign weren't from the same set of parties.");
            Err(CallerError::BadInput)?
        }

        // There shouldn't be duplicates.
        // This check is redundant, since it's also checked in the `auxinfo::Output` and
        // `keygen::Output` constructors, so we actually don't test it below.
        // Also, since we checked equality of the sets and the lengths already, checking
        // for keygen also validates it for auxinfo
        if key_pids.len() != keygen_output.public_key_shares().len() {
            error!("Duplicate participant IDs appeared in AuxInfo and KeyShare public input.");
            Err(CallerError::BadInput)?
        }

        // The constructors for keygen and auxinfo output already check other important
        // properties, like that the private component maps to one of public
        // components for each one.

        // The participant IDs for the private components of each output should match
        if keygen_output.private_pid() != auxinfo_output.private_pid() {
            error!("Expected private keygen and auxinfo outputs to correspond to the same participant, but they didn't");
            Err(CallerError::BadInput)?
        }

        Ok(Self {
            auxinfo_output,
            keygen_output,
        })
    }

    pub(crate) fn rid(&self) -> &[u8; 32] {
        self.keygen_output.rid()
    }

    pub(crate) fn public_key_shares(&self) -> &[KeySharePublic<C>] {
        self.keygen_output.public_key_shares()
    }

    /// Get the set of participants that contributed to the input.
    ///
    /// By construction, this must be the same for the auxinfo and key share
    /// lists.
    pub(crate) fn participants(&self) -> Vec<ParticipantIdentifier> {
        self.keygen_output
            .public_key_shares()
            .iter()
            .map(KeySharePublic::participant)
            .collect()
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

    /// Returns the [`KeySharePublic`] associated with the given
    /// [`ParticipantIdentifier`].
    pub(crate) fn find_keyshare_public(
        &self,
        pid: ParticipantIdentifier,
    ) -> Result<&KeySharePublic<C>> {
        self.keygen_output
            .public_key_shares()
            .iter()
            .find(|item| item.participant() == pid)
            .ok_or_else(|| {
                error!("Presign input doesn't contain a public keyshare for {}, even though we checked for it at construction.", pid);
                InternalError::InternalInvariantFailed
            })
    }

    /// Returns the [`AuxInfoPublic`]s associated with all the participants
    /// _except_ the given [`ParticipantIdentifier`].
    pub(crate) fn all_but_one_auxinfo_public(
        &self,
        pid: ParticipantIdentifier,
    ) -> Vec<&AuxInfoPublic> {
        self.auxinfo_output
            .public_auxinfo()
            .iter()
            .filter(|item| item.participant() != pid)
            .collect()
    }
    /// Returns a copy of the [`AuxInfoPublic`]s associated with all the
    /// participants (including this participant).
    pub(crate) fn to_public_auxinfo(&self) -> Vec<AuxInfoPublic> {
        self.auxinfo_output.public_auxinfo().to_vec()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        auxinfo,
        curve::TestCurve as C,
        errors::{CallerError, InternalError, Result},
        keygen,
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ParticipantIdentifier, PresignParticipant,
        ProtocolParticipant,
    };
    type Input = super::Input<C>;

    #[test]
    fn inputs_must_be_same_length() {
        let rng = &mut init_testing();

        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let keygen_output = keygen::Output::simulate(&pids, rng);
        let auxinfo_output = auxinfo::Output::simulate(&pids, rng);

        // Same length works
        let result = Input::new(auxinfo_output.clone(), keygen_output.clone());
        assert!(result.is_ok());

        // If keygen is too short, it fails.
        let short_keygen = keygen::Output::simulate(&pids[1..], rng);
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

        let auxinfo_pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let auxinfo_output = auxinfo::Output::simulate(&auxinfo_pids, rng);

        let keygen_pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let keygen_output = keygen::Output::simulate(&keygen_pids, rng);

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
        let input_pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(SIZE)
            .collect::<Vec<_>>();
        let keygen_output = keygen::Output::simulate(&input_pids, rng);
        let auxinfo_output = auxinfo::Output::simulate(&input_pids, rng);

        let input = Input::new(auxinfo_output, keygen_output)?;

        // Create valid config with PIDs independent of those used to make the input set
        let config = ParticipantConfig::random(SIZE, rng);

        let result = PresignParticipant::new(
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
