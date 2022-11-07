// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Runs the presignature generation protocol, producing a
//! [record::PresignRecord]

pub(crate) mod participant;
pub(crate) mod record;
pub(crate) mod round_one;
pub(crate) mod round_three;
pub(crate) mod round_two;
