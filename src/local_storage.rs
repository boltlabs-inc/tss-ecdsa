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

/// A type for storing values local to a protocol.
#[derive(Debug)]
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
            .map(|any| any.downcast_ref::<T::Value>().unwrap())
            .ok_or(InternalError::StorageItemNotFound)
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
            if !self.storage.contains_key(&(id, *pid, TypeId::of::<T>())) {
                return false;
            }
        }
        true
    }
}

impl Default for LocalStorage {
    fn default() -> Self {
        Self {
            storage: Default::default(),
        }
    }
}
