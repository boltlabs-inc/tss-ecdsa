// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::Result,
    paillier::{DecryptionKey, EncryptionKey},
    ring_pedersen::VerifiedRingPedersen,
};
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

/// The private key corresponding to a given Participant's [`AuxInfoPublic`].
#[derive(Serialize, Deserialize)]
pub(crate) struct AuxInfoPrivate {
    pub(crate) sk: DecryptionKey,
}

/// The public Auxilary Information corresponding to a given Participant.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoPublic {
    pub(crate) pk: EncryptionKey,
    pub(crate) params: VerifiedRingPedersen,
}

impl AuxInfoPublic {
    /// Verifies that the public key's modulus matches the ZKSetupParameters
    /// modulus N, and that the parameters have appropriate s and t values.
    pub(crate) fn verify(&self) -> Result<()> {
        if self.pk.modulus() != self.params.scheme().modulus() {
            return verify_err!("Mismatch between public key modulus and setup parameters modulus");
        }
        self.params.verify()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoWitnesses {
    pub(crate) p: BigNumber,
    pub(crate) q: BigNumber,
}
