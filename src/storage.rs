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
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};

/////////////////////////
// Private Storage API //
/////////////////////////

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "Persistent")]
pub(crate) enum PersistentStorageType {
    PrivateKeyshare,
    PublicKeyshare,
    MessageQueue,
    ProgressStore,
    AuxInfoPublic,
    AuxInfoPrivate,
    PresignRecord,
}

impl Storable for PersistentStorageType {}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
struct StorableIndex<T: Storable> {
    storable_type: T,
    /// The unique identifier associated with this stored value
    identifier: Identifier,
    // The participant identifier that this storable is associated with
    participant: ParticipantIdentifier,
}

impl<T: Storable> Storable for StorableIndex<T> {}

/// If a type implements `Storable` then it can be stored as an index into
/// [`Storage`].
pub(crate) trait Storable: Serialize + Copy + Debug {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Storage(HashMap<Vec<u8>, Vec<u8>>);

impl Storage {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    /// Stores `val` in its serialied form, using `storable_type`, `identifier`,
    /// and `associated_partipant_id` as the key.
    pub(crate) fn store<T: Storable, S: Serialize>(
        &mut self,
        storable_type: T,
        identifier: Identifier,
        associated_participant_id: ParticipantIdentifier,
        val: &S,
    ) -> Result<()> {
        let storable_index = StorableIndex {
            storable_type,
            identifier,
            participant: associated_participant_id,
        };
        self.store_index(storable_index, &serialize!(&val)?)
    }

    /// Retrieves an item in its deserialized form, using `storable_type`,
    /// `identifier`, and `associated_partipant_id` as the key.
    pub(crate) fn retrieve<T: Storable, D: DeserializeOwned>(
        &self,
        storable_type: T,
        identifier: Identifier,
        participant: ParticipantIdentifier,
    ) -> Result<D> {
        deserialize!(&self.retrieve_index(StorableIndex {
            storable_type,
            identifier,
            participant,
        })?)
    }

    /// Transfers an entry stored in `self` to [`Storage`] specified by `other`.
    pub(crate) fn transfer<T: Storable, D: Serialize + DeserializeOwned>(
        &self,
        other: &mut Self,
        storable_type: T,
        identifier: Identifier,
        participant: ParticipantIdentifier,
    ) -> Result<()> {
        let data: D = self.retrieve(storable_type, identifier, participant)?;
        other.store(storable_type, identifier, participant, &data)?;
        Ok(())
    }

    pub(crate) fn delete<T: Storable>(
        &mut self,
        storable_type: T,
        identifier: Identifier,
        participant: ParticipantIdentifier,
    ) -> Result<Vec<u8>> {
        self.delete_index(StorableIndex {
            storable_type,
            identifier,
            participant,
        })
    }

    pub(crate) fn contains_batch<T: Storable>(
        &self,
        type_and_id: &[(T, Identifier, ParticipantIdentifier)],
    ) -> Result<bool> {
        let storable_indices: Vec<StorableIndex<T>> = type_and_id
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
    pub(crate) fn contains_for_all_ids<T: Storable>(
        &self,
        s_type: T,
        sid: Identifier,
        participants: &[ParticipantIdentifier],
    ) -> Result<bool> {
        let fetch: Vec<(T, Identifier, ParticipantIdentifier)> = participants
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
        self.0
            .get(&key)
            .ok_or(InternalError::StorageItemNotFound)
            .cloned()
    }

    fn delete_index<I: Storable>(&mut self, storable_index: I) -> Result<Vec<u8>> {
        let key = serialize!(&storable_index)?;
        self.0
            .remove(&key)
            .ok_or(InternalError::StorageItemNotFound)
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
