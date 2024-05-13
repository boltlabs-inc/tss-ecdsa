// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The `LocalStorage` type for storing data local to a protocol.
//!
//! [`LocalStorage`] provides a means for storing values associated with a
//! [`TypeTag`] and [`ParticipantIdentifier`]. Values can
//! be either stored, retrieved, and looked up in the storage.

use tracing::error;

use crate::{
    errors::{InternalError, Result},
    ParticipantIdentifier,
};
use std::{
    any::{Any, TypeId},
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
};

/// A type implementing `TypeTag` can be used to store and retrieve
/// values of type `<T as TypeTag>::Value`.
pub(crate) trait TypeTag: 'static {
    type Value: Send + Sync;
}

pub(crate) mod storage {
    use super::TypeTag;
    use std::collections::HashSet;

    pub(crate) struct MessageQueue;
    impl TypeTag for MessageQueue {
        type Value = crate::message_queue::MessageQueue;
    }

    pub(crate) struct ProgressStore;
    impl TypeTag for ProgressStore {
        type Value = HashSet<String>;
    }
}

/// A type for storing values local to a protocol.
#[derive(Debug, Default)]
pub(crate) struct LocalStorage {
    storage: HashMap<(ParticipantIdentifier, TypeId), Box<dyn Any + Send + Sync>>,
}

impl LocalStorage {
    /// Stores `value` via a [`TypeTag`] and
    /// [`ParticipantIdentifier`] tuple, overwriting any pre-existing value.
    pub(crate) fn store<T: TypeTag>(
        &mut self,
        participant_id: ParticipantIdentifier,
        value: T::Value,
    ) {
        let _ = self
            .storage
            .insert((participant_id, TypeId::of::<T>()), Box::new(value));
    }

    /// Stores `value` via a [`TypeTag`] and
    /// [`ParticipantIdentifier`] tuple. Fails if a value exists.
    pub(crate) fn store_once<T: TypeTag>(
        &mut self,
        participant_id: ParticipantIdentifier,
        value: T::Value,
    ) -> Result<()> {
        match self.storage.entry((participant_id, TypeId::of::<T>())) {
            Vacant(entry) => {
                let _ = entry.insert(Box::new(value));
                Ok(())
            }
            Occupied(_) => {
                error!(
                    "Storage entry already exists. Type: {:?}, participant_id: {}",
                    std::any::type_name::<T::Value>(),
                    participant_id
                );
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    /// Retrieves a reference to a value via its [`TypeTag`] and
    /// [`ParticipantIdentifier`]. This will return an error if the item is
    /// not in storage and should only be called after first checking with
    /// [`contains()`](LocalStorage::contains())
    /// or [`contains_for_all_ids()`](LocalStorage::contains_for_all_ids())
    pub(crate) fn retrieve<T: TypeTag>(
        &self,
        participant_id: ParticipantIdentifier,
    ) -> Result<&T::Value> {
        self.storage
            .get(&(participant_id, TypeId::of::<T>()))
            .map(|any| {
                any.downcast_ref::<T::Value>().ok_or_else(|| {
                    error!(
                        "Could not downcast storage entry. Type: {:?}, participant_id: {}",
                        std::any::type_name::<T::Value>(),
                        participant_id
                    );
                    InternalError::InternalInvariantFailed
                })
            })
            .unwrap_or_else(|| {
                error!(
                    "Could not retrieve storage entry. Type: {:?}, participant_id: {}",
                    std::any::type_name::<T::Value>(),
                    participant_id
                );
                Err(InternalError::InternalInvariantFailed)
            })
    }

    /// Deletes a storage value via its [`TypeTag`] and
    /// [`ParticipantIdentifier`]. This function returns the deleted value if it
    /// existed and should be used instead of
    /// [`retrieve()`](LocalStorage::retrieve()) if the value is being
    /// accessed for the last time.
    pub(crate) fn remove<T: TypeTag>(
        &mut self,
        participant_id: ParticipantIdentifier,
    ) -> Result<T::Value> {
        self.storage
            .remove(&(participant_id, TypeId::of::<T>()))
            .ok_or_else(|| {
                error!(
                    "Could not locate storage entry. Type: {:?}, participant_id: {}",
                    std::any::type_name::<T::Value>(),
                    participant_id
                );
                InternalError::InternalInvariantFailed
            })?
            .downcast::<T::Value>()
            .map_err(|_| {
                error!(
                    "Could not downcast storage entry. Type: {:?}, participant_id: {}",
                    std::any::type_name::<T::Value>(),
                    participant_id
                );
                InternalError::InternalInvariantFailed
            })
            .map(|any| *any)
    }

    /// Retrieves a mutable reference to a value via its [`TypeTag`]
    /// and [`ParticipantIdentifier`].
    pub(crate) fn retrieve_mut<T: TypeTag>(
        &mut self,
        participant_id: ParticipantIdentifier,
    ) -> Option<&mut T::Value> {
        match self.storage.get_mut(&(participant_id, TypeId::of::<T>())) {
            Some(any) => any.downcast_mut::<T::Value>(),
            None => None,
        }
    }

    /// Checks whether values exist for the given [`TypeTag`]
    /// and each of the `participant_ids` provided, returning `true` if so
    /// and `false` otherwise.
    pub(crate) fn contains_for_all_ids<T: TypeTag>(
        &self,
        participant_ids: &[ParticipantIdentifier],
    ) -> bool {
        for pid in participant_ids {
            if !self.contains::<T>(*pid) {
                return false;
            }
        }
        true
    }

    /// Returns `true` if a value exists for the given [`TypeTag`]
    /// and [`ParticipantIdentifier`].
    pub(crate) fn contains<T: TypeTag>(&self, participant_id: ParticipantIdentifier) -> bool {
        self.storage
            .contains_key(&(participant_id, TypeId::of::<T>()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{message_queue::MessageQueue, utils::testing::init_testing};

    #[test]
    fn local_storage_store_once() -> Result<()> {
        let rng = &mut init_testing();
        let pid = ParticipantIdentifier::random(rng);

        let mut storage = LocalStorage::default();
        storage.store_once::<storage::MessageQueue>(pid, MessageQueue::default())?;

        assert!(storage.contains::<storage::MessageQueue>(pid));
        assert!(storage.retrieve::<storage::MessageQueue>(pid).is_ok());

        let store_again = storage.store_once::<storage::MessageQueue>(pid, MessageQueue::default());
        assert!(store_again.is_err());

        Ok(())
    }
}
