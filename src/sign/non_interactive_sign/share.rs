// Copyright (c) 2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use serde::{Deserialize, Serialize};

use crate::{
    curve::CT, errors::{InternalError, Result}, messages::{Message, MessageType, SignMessageType}
};

/// A single participant's share of the signature.
#[allow(unused)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureShare<C: CT>(pub C::Scalar);

impl<C: CT> SignatureShare<C> {
    pub(super) fn new(share: C::Scalar) -> Self {
        Self(share)
    }
}

impl<C: CT> TryFrom<&Message> for SignatureShare<C> {
    type Error = InternalError;

    fn try_from(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Sign(SignMessageType::RoundOneShare))?;

        // There's no additional verification here; the `Scalar` type ensures that the
        // value is in range.
        deserialize!(&message.unverified_bytes)
    }
}

impl<C: CT> std::ops::Add<SignatureShare<C>> for SignatureShare<C> {
    type Output = C::Scalar;
    fn add(self, rhs: SignatureShare<C>) -> Self::Output {
        self.0.add(rhs.0)
    }
}

/*impl<C: CT> std::ops::Add<SignatureShare<C>> for C::Scalar {
    type Output = Self;
    fn add(self, rhs: SignatureShare<C>) -> Self::Output {
        self.add(&rhs.0)
    }
}*/
