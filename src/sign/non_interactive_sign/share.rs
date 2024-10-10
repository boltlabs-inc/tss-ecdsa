// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use k256::Scalar;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{InternalError, Result},
    messages::{Message, MessageType, SignMessageType},
};

/// A single participant's share of the signature.
#[allow(unused)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare(pub Scalar);

impl SignatureShare {
    pub(super) fn new(share: Scalar) -> Self {
        Self(share)
    }
}

impl TryFrom<&Message> for SignatureShare {
    type Error = InternalError;

    fn try_from(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Sign(SignMessageType::RoundOneShare))?;

        // There's no additional verification here; the `Scalar` type ensures that the
        // value is in range.
        deserialize!(&message.unverified_bytes)
    }
}

impl std::ops::Add<SignatureShare> for SignatureShare {
    type Output = Scalar;
    fn add(self, rhs: SignatureShare) -> Self::Output {
        self.0 + rhs.0
    }
}

impl std::ops::Add<SignatureShare> for Scalar {
    type Output = Self;
    fn add(self, rhs: SignatureShare) -> Self::Output {
        self + rhs.0
    }
}
