// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The `LocalStorage` type for storing data local to a protocol.
//!
//! [`LocalStorage`] provides a means for storing values associated with a
//! [`TypeTag`], [`Identifier`], and [`ParticipantIdentifier`] tuple. Values can
//! be either stored, retrieved, and looked up in the storage.

use crate::{
    errors::{InternalError, Result},
    storage::{PersistentStorageType, Storage},
    Identifier, ParticipantIdentifier,
};
use std::{
    any::{Any, TypeId},
    collections::HashMap,
};

/// A type implementing `TypeTag` can be used to store and retrieve
/// values of type `<T as TypeTag>::Value`.
pub(crate) trait TypeTag: 'static {
    type Value: Send + Sync;
}

pub(crate) mod storage {
    use super::TypeTag;
    use std::collections::HashMap;

    pub(crate) struct MessageQueue;
    impl TypeTag for MessageQueue {
        type Value = crate::message_queue::MessageQueue;
    }

    pub(crate) struct ProgressStore;
    impl TypeTag for ProgressStore {
        type Value = HashMap<Vec<u8>, bool>;
    }
}

/// A type for storing values local to a protocol.
#[derive(Debug, Default)]
pub(crate) struct LocalStorage {
    storage: HashMap<(Identifier, ParticipantIdentifier, TypeId), Box<dyn Any + Send + Sync>>,
}

impl LocalStorage {
    /// Stores `value` via a [`TypeTag`], [`Identifier`], and
    /// [`ParticipantIdentifier`] tuple.
    pub(crate) fn store<T: TypeTag>(
        &mut self,
        id: Identifier,
        participant_id: ParticipantIdentifier,
        value: T::Value,
    ) {
        let _ = self
            .storage
            .insert((id, participant_id, TypeId::of::<T>()), Box::new(value));
    }

    /// Retrieves a reference to a value via its [`TypeTag`], [`Identifier`],
    /// and [`ParticipantIdentifier`].
    pub(crate) fn retrieve<T: TypeTag>(
        &self,
        id: Identifier,
        participant_id: ParticipantIdentifier,
    ) -> Result<&T::Value> {
        self.storage
            .get(&(id, participant_id, TypeId::of::<T>()))
            .map(|any| {
                any.downcast_ref::<T::Value>()
                    .ok_or(InternalError::InternalInvariantFailed)
            })
            .unwrap_or(Err(InternalError::StorageItemNotFound))
    }

    /// Retrieves a mutable reference to a value via its [`TypeTag`],
    /// [`Identifier`], and [`ParticipantIdentifier`].
    pub(crate) fn retrieve_mut<T: TypeTag>(
        &mut self,
        id: Identifier,
        participant_id: ParticipantIdentifier,
    ) -> Result<&mut T::Value> {
        self.storage
            .get_mut(&(id, participant_id, TypeId::of::<T>()))
            .map(|any| {
                any.downcast_mut::<T::Value>()
                    .ok_or(InternalError::InternalInvariantFailed)
            })
            .unwrap_or(Err(InternalError::StorageItemNotFound))
    }

    /// Transfers an item associated with the given [`TypeTag`] in local storage
    /// to `main_storage`, using the [`PersistentStorageType`],
    /// [`Identifier`] and [`ParticipantIdentifier`] tuple as the persistent
    /// storage key.
    pub(crate) fn transfer<T: TypeTag>(
        &self,
        main_storage: &mut Storage,
        storage_type: PersistentStorageType,
        id: Identifier,
        participant_id: ParticipantIdentifier,
    ) -> Result<()>
    where
        T::Value: serde::Serialize,
    {
        let item = self.retrieve::<T>(id, participant_id)?;
        main_storage.store(storage_type, id, participant_id, item)?;
        Ok(())
    }

    /// Checks whether values exist for the given [`TypeTag`], [`Identifier`],
    /// and each of the `participant_ids` provided, returning `true` if so
    /// and `false` otherwise.
    pub(crate) fn contains_for_all_ids<T: TypeTag>(
        &self,
        id: Identifier,
        participant_ids: &[ParticipantIdentifier],
    ) -> bool {
        for pid in participant_ids {
            if !self.contains::<T>(id, *pid) {
                return false;
            }
        }
        true
    }

    /// Returns `true` if a value exists for the given [`TypeTag`],
    /// [`Identifier`], and [`ParticipantIdentifier`].
    pub(crate) fn contains<T: TypeTag>(
        &self,
        id: Identifier,
        participant_id: ParticipantIdentifier,
    ) -> bool {
        self.storage
            .contains_key(&(id, participant_id, TypeId::of::<T>()))
    }
}
