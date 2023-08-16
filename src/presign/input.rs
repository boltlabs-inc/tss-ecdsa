use std::collections::HashSet;

use tracing::error;

use crate::{
    auxinfo::{self, AuxInfoPrivate, AuxInfoPublic},
    errors::{CallerError, InternalError, Result},
    keygen::{self, KeySharePrivate, KeySharePublic},
    ParticipantIdentifier,
};

/// Input needed for a
/// [`PresignParticipant`](crate::presign::PresignParticipant) to run.
#[derive(Debug, Clone)]
pub struct Input {
    /// The key share material for the key that will be used in the presign run.
    keygen_output: keygen::Output,
    /// The auxiliary info for the key that will be used in the presign run.
    auxinfo_output: auxinfo::Output,
}

impl Input {
    /// Creates a new [`Input`] from the outputs of the
    /// [`auxinfo`](crate::auxinfo::AuxInfoParticipant) and
    /// [`keygen`](crate::keygen::KeygenParticipant) protocols.
    pub fn new(auxinfo_output: auxinfo::Output, keygen_output: keygen::Output) -> Result<Self> {
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
            .map(KeySharePublic::participant)
            .collect::<HashSet<_>>();
        if aux_pids != key_pids {
            error!("Public auxinfo and keyshare inputs to presign weren't from the same set of parties.");
            Err(CallerError::BadInput)?
        }

        // There shouldn't be duplicates. Since we checked equality of the sets and the
        // lengths already, this also applies to auxinfo (also, the `auxinfo::Output`
        // type checks this at construction already).
        if key_pids.len() != keygen_output.public_key_shares().len() {
            error!("Duplicate participant IDs appeared in AuxInfo and KeyShare public input.");
            Err(CallerError::BadInput)?
        }

        // The private key share should map to one of the public values.
        // NB: The corresponding check for `auxinfo::Output` is handled in that type's
        // constructor.
        let expected_public_share = keygen_output.private_key_share().public_share()?;
        if !keygen_output
            .public_key_shares()
            .iter()
            .any(|public_share| expected_public_share == *public_share.as_ref())
        {
            error!("Keygen private share did not correspond to any of the provided keygen public shares.");
            Err(CallerError::BadInput)?
        }

        Ok(Self {
            auxinfo_output,
            keygen_output,
        })
    }

    pub(crate) fn public_key_shares(&self) -> &[KeySharePublic] {
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

    pub(crate) fn private_key_share(&self) -> &KeySharePrivate {
        self.keygen_output.private_key_share()
    }

    /// Returns the [`KeySharePublic`] associated with the given
    /// [`ParticipantIdentifier`].
    pub(crate) fn find_keyshare_public(
        &self,
        pid: ParticipantIdentifier,
    ) -> Result<&KeySharePublic> {
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
    use super::Input;
    use crate::{
        auxinfo,
        errors::{CallerError, InternalError, Result},
        keygen,
        utils::testing::init_testing,
        Identifier, ParticipantConfig, ParticipantIdentifier, PresignParticipant,
        ProtocolParticipant,
    };

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
    fn inputs_must_not_have_duplicates() {
        let rng = &mut init_testing();

        let mut pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();

        // This test doesn't bother adding a duplicate in only one of the inputs because
        // that would fail the length checks tested in `inputs_must_be_same_length`
        // Instead, duplicate one of the PIDs...
        pids.push(pids[4]);

        // ...and simulate the outputs. The public material will be different for the
        // two duplicated PIDs.
        let keygen_output = keygen::Output::simulate(&pids, rng);
        let auxinfo_output = auxinfo::Output::simulate(&pids, rng);

        let result = Input::new(auxinfo_output, keygen_output);
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
