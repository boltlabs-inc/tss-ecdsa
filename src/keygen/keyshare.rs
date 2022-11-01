// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::utils::CurvePoint;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

/// Private key corresponding to a given [KeySharePublic]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeySharePrivate {
    pub(crate) x: BigNumber, // in the range [1, q)
}

/// A CurvePoint representing a given Participant's public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeySharePublic {
    pub(crate) X: CurvePoint,
}
