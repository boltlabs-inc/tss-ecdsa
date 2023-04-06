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

use crate::{
    errors::{InternalError, Result},
    ParticipantIdentifier,
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
        type Value = HashMap<crate::participant::ProgressIndex, bool>;
    }
}

/// A type for storing values local to a protocol.
#[derive(Debug, Default)]
pub(crate) struct LocalStorage {
    storage: HashMap<(ParticipantIdentifier, TypeId), Box<dyn Any + Send + Sync>>,
}

impl LocalStorage {
    /// Stores `value` via a [`TypeTag`] and
    /// [`ParticipantIdentifier`] tuple.
    pub(crate) fn store<T: TypeTag>(
        &mut self,
        participant_id: ParticipantIdentifier,
        value: T::Value,
    ) {
        let _ = self
            .storage
            .insert((participant_id, TypeId::of::<T>()), Box::new(value));
    }

    /// Retrieves a reference to a value via its [`TypeTag`]
    /// and [`ParticipantIdentifier`].
    pub(crate) fn retrieve<T: TypeTag>(
        &self,
        participant_id: ParticipantIdentifier,
    ) -> Result<&T::Value> {
        self.storage
            .get(&(participant_id, TypeId::of::<T>()))
            .map(|any| {
                any.downcast_ref::<T::Value>()
                    .ok_or(InternalError::InternalInvariantFailed)
            })
            .unwrap_or(Err(InternalError::StorageItemNotFound))
    }

    /// Retrieves a mutable reference to a value via its [`TypeTag`]
    /// and [`ParticipantIdentifier`].
    pub(crate) fn retrieve_mut<T: TypeTag>(
        &mut self,
        participant_id: ParticipantIdentifier,
    ) -> Result<&mut T::Value> {
        self.storage
            .get_mut(&(participant_id, TypeId::of::<T>()))
            .map(|any| {
                any.downcast_mut::<T::Value>()
                    .ok_or(InternalError::InternalInvariantFailed)
            })
            .unwrap_or(Err(InternalError::StorageItemNotFound))
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
