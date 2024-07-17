// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    curve_point::{CurvePoint, CurveTrait}, errors::{InternalError, Result}, keyrefresh::keyshare::KeyUpdatePublic, messages::{KeyrefreshMessageType, Message, MessageType}, protocol::{Identifier, ParticipantIdentifier}
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::error;

/// Public commitment to `KeyrefreshDecommit` in round 1.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct KeyrefreshCommit {
    hash: [u8; 32],
}
impl KeyrefreshCommit {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Keyrefresh(KeyrefreshMessageType::R1CommitHash))?;
        let keyrefresh_commit: KeyrefreshCommit = deserialize!(&message.unverified_bytes)?;
        Ok(keyrefresh_commit)
    }
}

/// Decommitment published in round 2.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct KeyrefreshDecommit<C: CurveTrait> {
    sid: Identifier,
    sender: ParticipantIdentifier,
    u_i: [u8; 32], // The blinding factor is never read but it is included in the commitment.
    pub rid: [u8; 32],
    pub update_publics: Vec<KeyUpdatePublic<C>>,
    pub As: Vec<C>,
}

/// Implement custom serialization for KeyrefreshDecommit.
/*impl<C: CurveTrait> Serialize for KeyrefreshDecommit<C> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut ser = s.serialize_struct("KeyrefreshDecommit", 5)?;
        ser.serialize_field("sid", &self.sid)?;
        ser.serialize_field("sender", &self.sender)?;
        ser.serialize_field("u_i", &self.u_i)?;
        ser.serialize_field("rid", &self.rid)?;
        ser.serialize_field("update_publics", &self.update_publics)?;
        ser.end()
    }
}*/

/// FIXME: Next function is calling itself, causing overflow in the stack. But code finally compiles.
/*impl<'de, C: CurveTrait> Deserialize<'de> for KeyrefreshDecommit<C> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let keyrefresh_decommit: KeyrefreshDecommit<C> = serde::Deserialize::deserialize(deserializer)?;
        Ok(keyrefresh_decommit)
    }
}*/

/// Deserialize by deserializing each field individually in order to avoid C: CurveTrait bound.
/*impl<'de, C: CurveTrait> Deserialize<'de> for KeyrefreshDecommit<C> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        struct KeyrefreshDecommitVisitor<C: CurveTrait> {
            marker: std::marker::PhantomData<C>,
        }

        impl<'de, C: CurveTrait> serde::de::Visitor<'de> for KeyrefreshDecommitVisitor<C> {
            type Value = KeyrefreshDecommit<C>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyrefreshDecommit")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut sid = None;
                let mut sender = None;
                let mut u_i = None;
                let mut rid = None;
                let mut update_publics = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "sid" => {
                            if sid.is_some() {
                                return Err(serde::de::Error::duplicate_field("sid"));
                            }
                            sid = Some(map.next_value()?);
                        }
                        "sender" => {
                            if sender.is_some() {
                                return Err(serde::de::Error::duplicate_field("sender"));
                            }
                            sender = Some(map.next_value()?);
                        }
                        "u_i" => {
                            if u_i.is_some() {
                                return Err(serde::de::Error::duplicate_field("u_i"));
                            }
                            u_i = Some(map.next_value()?);
                        }
                        "rid" => {
                            if rid.is_some() {
                                return Err(serde::de::Error::duplicate_field("rid"));
                            }
                            rid = Some(map.next_value()?);
                        }
                        "update_publics" => {
                            if update_publics.is_some() {
                                return Err(serde::de::Error::duplicate_field("update_publics"));
                            }
                            update_publics = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key, 
                                &["sid", 
                                "sender", 
                                "u_i", 
                                "rid", 
                                "update_publics"]));
                        }
                    }
                }

                let sid = sid.ok_or_else(|| serde::de::Error::missing_field("sid"))?;
                let sender = sender.ok_or_else(|| serde::de::Error::missing_field("sender"))?;
                let u_i = u_i.ok_or_else(|| serde::de::Error::missing_field("u_i"))?;
                let rid = rid.ok_or_else(|| serde::de::Error::missing_field("rid"))?;
                let update_publics = update_publics.ok_or_else(|| serde::de::Error::missing_field("update_publics"))?;

                Ok(KeyrefreshDecommit {
                    sid,
                    sender,
                    u_i,
                    rid,
                    update_publics,
                    As: Vec::new(),
                })
            }
        }

        deserializer.deserialize_struct("KeyrefreshDecommit", &["sid", "sender", "u_i", "rid", "update_publics"], KeyrefreshDecommitVisitor { marker: std::marker::PhantomData })
    }
}*/

impl<'de, C: CurveTrait + Serialize + Deserialize<'de>> KeyrefreshDecommit<C> {
    ///`sid` corresponds to a unique session identifier.
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        sid: &Identifier,
        sender: &ParticipantIdentifier,
        update_publics: Vec<KeyUpdatePublic<C>>,
        sch_precoms: Vec<C>,
    ) -> Self {
        let mut rid = [0u8; 32];
        let mut u_i = [0u8; 32];
        rng.fill_bytes(rid.as_mut_slice());
        rng.fill_bytes(u_i.as_mut_slice());
        Self {
            sid: *sid,
            sender: *sender,
            rid,
            u_i,
            update_publics,
            As: sch_precoms,
        }
    }

    /// Deserialize a KeyrefreshDecommit from a message and verify it.
    pub(crate) fn from_message(
        message: &'de Message,
        com: &KeyrefreshCommit,
        participant_ids: &[ParticipantIdentifier],
    ) -> Result<Self> {
        message.check_type(MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit))?;
        let keyrefresh_decommit: KeyrefreshDecommit<C> = deserialize!(&message.unverified_bytes)?;
        keyrefresh_decommit.verify(message.id(), message.from(), com, participant_ids)?;
        Ok(keyrefresh_decommit)
    }

    pub(crate) fn commit(&self) -> Result<KeyrefreshCommit> {
        let mut transcript = Transcript::new(b"KeyRefreshR1");
        transcript.append_message(b"decom", &serialize!(&self)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"hashing r1", &mut hash);
        Ok(KeyrefreshCommit { hash })
    }

    /// Verify this KeyrefreshDecommit against a commitment and expected
    /// content.
    fn verify(
        &self,
        sid: Identifier,
        sender: ParticipantIdentifier,
        com: &KeyrefreshCommit,
        participant_ids: &[ParticipantIdentifier],
    ) -> Result<()> {
        // Check the commitment.
        let rebuilt_com = self.commit()?;
        if &rebuilt_com != com {
            error!("decommitment does not match original commitment");
            return Err(InternalError::ProtocolError(Some(sender)));
        }

        // Check the session ID and sender ID.
        if self.sid != sid {
            error!("Incorrect session ID");
            return Err(InternalError::ProtocolError(Some(sender)));
        }
        if self.sender != sender {
            error!("Incorrect sender ID");
            return Err(InternalError::ProtocolError(Some(sender)));
        }

        // Check the number of commitments As.
        if self.As.len() != participant_ids.len() {
            error!("Incorrect number of As");
            return Err(InternalError::ProtocolError(Some(sender)));
        }

        // Check the set of participants.
        if self.update_publics.len() != participant_ids.len() {
            error!("Incorrect number of update publics");
            return Err(InternalError::ProtocolError(Some(sender)));
        }
        for kup in &self.update_publics {
            if !participant_ids.contains(&kup.participant()) {
                error!("Invalid set of participant IDs in KeyrefreshDecommit");
                return Err(InternalError::ProtocolError(Some(sender)));
            }
        }

        // Check that the sum of key updates is identity, i.e. it will not change our
        // public key.
        let sum = KeyUpdatePublic::sum(sender, &self.update_publics);
        if sum.as_ref() != &CurvePoint::IDENTITY {
            error!("Sum of key updates is not identity");
            return Err(InternalError::ProtocolError(Some(sender)));
        }

        Ok(())
    }
}

// Implement custom Debug to avoid leaking secret information.
impl<C: CurveTrait> std::fmt::Debug for KeyrefreshDecommit<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyrefreshDecommit")
            .field("sid", &self.sid)
            .field("sender", &self.sender)
            .field("...", &"[redacted]")
            .finish()
    }
}
