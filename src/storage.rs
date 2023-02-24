// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{InternalError, Result},
    protocol::{Identifier, ParticipantIdentifier},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug, hash::Hash};

/////////////////////////
// Private Storage API //
/////////////////////////

#[derive(Debug, Copy, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub(crate) enum StorableType {
    KeygenReady,
    KeygenCommit,
    KeygenDecommit,
    KeygenSchnorrPrecom,
    KeygenGlobalRid,
    AuxInfoReady,
    AuxInfoPrivate,
    AuxInfoPublic,
    AuxInfoCommit,
    AuxInfoDecommit,
    AuxInfoGlobalRid,
    AuxInfoWitnesses,
    PrivateKeyshare,
    PublicKeyshare,
    PresignReady,
    PresignRoundOnePrivate,
    PresignRoundOnePublic,
    PresignRoundOnePublicBroadcast,
    PresignRoundTwoPrivate,
    PresignRoundTwoPublic,
    PresignRoundThreePrivate,
    PresignRoundThreePublic,
    PresignRecord,
    MessageQueue,
    ProgressStore,
    BroadcastSet,
}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug, Serialize, Deserialize)]
struct StorableIndex {
    storable_type: StorableType,
    /// The unique identifier associated with this stored value
    identifier: Identifier,
    // The participant identifier that this storable is associated with
    participant: ParticipantIdentifier,
}

impl Storable for StorableIndex {}

pub(crate) trait Storable: Serialize + Debug {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Storage(HashMap<Vec<u8>, Vec<u8>>);

impl Storage {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    pub(crate) fn store(
        &mut self,
        storable_type: StorableType,
        identifier: Identifier,
        associated_participant_id: ParticipantIdentifier,
        val: &[u8],
    ) -> Result<()> {
        let storable_index = StorableIndex {
            storable_type,
            identifier,
            participant: associated_participant_id,
        };
        self.store_index(storable_index, val)
    }

    pub(crate) fn retrieve(
        &self,
        storable_type: StorableType,
        identifier: Identifier,
        participant: ParticipantIdentifier,
    ) -> Result<Vec<u8>> {
        self.retrieve_index(StorableIndex {
            storable_type,
            identifier,
            participant,
        })
    }

    /// Transfers an entry stored in `self` to [`Storage`] specified by `other`.
    pub(crate) fn transfer(
        &self,
        other: &mut Self,
        storable_type: StorableType,
        identifier: Identifier,
        participant: ParticipantIdentifier,
    ) -> Result<()> {
        let bytes = self.retrieve(storable_type, identifier, participant)?;
        other.store(storable_type, identifier, participant, &bytes)?;
        Ok(())
    }

    pub(crate) fn delete(
        &mut self,
        storable_type: StorableType,
        identifier: Identifier,
        participant: ParticipantIdentifier,
    ) -> Result<Vec<u8>> {
        self.delete_index(StorableIndex {
            storable_type,
            identifier,
            participant,
        })
    }

    pub(crate) fn contains_batch(
        &self,
        type_and_id: &[(StorableType, Identifier, ParticipantIdentifier)],
    ) -> Result<bool> {
        let storable_indices: Vec<StorableIndex> = type_and_id
            .iter()
            .map(|(t, identifier, participant)| StorableIndex {
                storable_type: *t,
                identifier: *identifier,
                participant: *participant,
            })
            .collect();
        self.contains_index_batch(&storable_indices)
    }

    /// Check if storage contains entries for a given StorableType for each
    /// listed ParticipantIdentifier (in the same sid)
    pub(crate) fn contains_for_all_ids(
        &self,
        s_type: StorableType,
        sid: Identifier,
        participants: &[ParticipantIdentifier],
    ) -> Result<bool> {
        let fetch: Vec<(StorableType, Identifier, ParticipantIdentifier)> = participants
            .iter()
            .map(|participant| (s_type, sid, *participant))
            .collect();
        self.contains_batch(&fetch)
    }

    // Inner functions

    fn store_index<I: Storable>(&mut self, storable_index: I, val: &[u8]) -> Result<()> {
        let key = serialize!(&storable_index)?;
        let _ = self.0.insert(key, val.to_vec());
        Ok(())
    }

    fn retrieve_index<I: Storable>(&self, storable_index: I) -> Result<Vec<u8>> {
        let key = serialize!(&storable_index)?;
        let ret = self
            .0
            .get(&key)
            .ok_or_else(|| InternalError::StorageItemNotFound)?
            .clone();

        Ok(ret)
    }

    fn delete_index<I: Storable>(&mut self, storable_index: I) -> Result<Vec<u8>> {
        let key = serialize!(&storable_index)?;
        self.0
            .remove(&key)
            .ok_or_else(|| InternalError::StorageItemNotFound)
    }

    fn contains_index_batch<I: Storable>(&self, storable_indices: &[I]) -> Result<bool> {
        for storable_index in storable_indices {
            let key = serialize!(&storable_index)?;
            let ret = self.0.contains_key(&key);
            if !ret {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
