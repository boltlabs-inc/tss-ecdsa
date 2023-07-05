// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::{CallerError, InternalError, Result},
    paillier::{DecryptionKey, EncryptionKey},
    ring_pedersen::VerifiedRingPedersen,
    utils::ParseBytes,
    zkp::ProofContext,
    ParticipantIdentifier,
};
use k256::elliptic_curve::zeroize::ZeroizeOnDrop;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::{error, instrument};
use zeroize::Zeroize;
/// Private auxiliary information for a specific
/// [`Participant`](crate::Participant).
///
/// This includes a Paillier decryption key; there should be a corresponding
/// [`AuxInfoPublic`] with the encryption key and ring-Pedersen commitment
/// parameters formed with the same modulus.
///
/// Note: this doesn't implement [`ZeroizeOnDrop`](https://docs.rs/zeroize/latest/zeroize/)
/// but all of its internal types do.
///
/// # 🔒 Storage requirements
/// This type must be stored securely by the calling application.
#[derive(Clone, PartialEq, Eq)]
pub struct AuxInfoPrivate {
    /// The participant's Paillier private key.
    decryption_key: DecryptionKey,
}

const AUXINFO_TAG: &[u8] = b"AuxInfoPrivate";

impl AuxInfoPrivate {
    pub(crate) fn encryption_key(&self) -> EncryptionKey {
        self.decryption_key.encryption_key()
    }

    pub(crate) fn decryption_key(&self) -> &DecryptionKey {
        &self.decryption_key
    }

    /// Convert private material into bytes.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. The output of this function should be handled with care.
    pub fn into_bytes(self) -> Vec<u8> {
        // Format:
        // AUXINFO_TAG | key_len in bytes | key
        //             | ---8 bytes------ | --key_len bytes---

        let mut key = self.decryption_key.into_bytes();
        let key_len = key.len().to_le_bytes();

        let bytes = [AUXINFO_TAG, &key_len, &key].concat();
        key.zeroize();
        bytes
    }

    /// Convert bytes into private material.
    ///
    /// 🔒 This is intended for use by the calling application for secure
    /// storage. Do not use this method to create arbitrary instances of
    /// [`AuxInfoPrivate`].
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Expected format:
        // AUXINFO_TAG | key_len in bytes | key
        //             | ---8 bytes------ | --key_len bytes---

        let mut parser = ParseBytes::new(bytes);

        // This little closure ensures that
        // 1. We can zeroize out the potentially-sensitive input bytes regardless of
        //    whether parsing succeeded; and
        // 2. We can log the error message once at the end, rather than duplicating it
        //    across all the parsing code
        let mut parse = || {
            // Make sure the AUXINFO_TAG is correct
            let actual_tag = parser.take_bytes(AUXINFO_TAG.len())?;
            if actual_tag != AUXINFO_TAG {
                Err(CallerError::DeserializationFailed)?
            }

            // Extract the length of the key
            let key_len = parser.take_len()?;

            let key_bytes = parser.take_rest()?;
            if key_bytes.len() != key_len {
                Err(CallerError::DeserializationFailed)?
            }

            // Check the key
            let decryption_key = DecryptionKey::try_from_bytes(key_bytes)
                .map_err(|_| CallerError::DeserializationFailed)?;

            Ok(Self { decryption_key })
        };

        let result = parse();

        // When creating the `DecryptionKey`, the secret bytes get copied. Here, we
        // delete the original copy.
        parser.zeroize();

        if result.is_err() {
            error!(
                "Failed to deserialize `AuxInfoPrivate. Expected format:
                        {:?} | key_len | key
                        where `key_len` is a little-endian encoded usize
                        and `key` is exactly `key_len` bytes long.",
                AUXINFO_TAG
            );
        }
        result
    }
}

impl From<DecryptionKey> for AuxInfoPrivate {
    fn from(decryption_key: DecryptionKey) -> Self {
        Self { decryption_key }
    }
}

impl Debug for AuxInfoPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxInfoPrivate")
            .field("decryption_key", &"[redacted]")
            .finish()
    }
}

/// The public auxilary information for a specific
/// [`Participant`](crate::Participant).
///
/// This includes a Paillier encryption key and corresponding ring-Pedersen
/// commitment parameters.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AuxInfoPublic {
    /// The participant's identifier.
    participant: ParticipantIdentifier,
    /// The participant's Paillier public key.
    pk: EncryptionKey,
    /// The participant's (verified) ring-Pedersen parameters.
    params: VerifiedRingPedersen,
}

impl AuxInfoPublic {
    pub(crate) fn new(
        context: &impl ProofContext,
        participant: ParticipantIdentifier,
        encryption_key: EncryptionKey,
        params: VerifiedRingPedersen,
    ) -> Result<Self> {
        let public = Self {
            participant,
            pk: encryption_key,
            params,
        };
        public.verify(context)?;
        Ok(public)
    }

    pub(crate) fn pk(&self) -> &EncryptionKey {
        &self.pk
    }

    pub(crate) fn params(&self) -> &VerifiedRingPedersen {
        &self.params
    }

    pub(crate) fn participant(&self) -> ParticipantIdentifier {
        self.participant
    }

    /// Verifies that the public key's modulus matches the ZKSetupParameters
    /// modulus N, and that the parameters have appropriate s and t values.
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn verify(&self, context: &impl ProofContext) -> Result<()> {
        if self.pk.modulus() != self.params.scheme().modulus() {
            error!("Mismatch between public key modulus and setup parameters modulus");
            return Err(InternalError::Serialization);
        }
        self.params.verify(context)
    }
}

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct AuxInfoWitnesses {
    pub(crate) p: BigNumber,
    pub(crate) q: BigNumber,
}

impl Debug for AuxInfoWitnesses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuxInfoWitnesses")
            .field("p", &"[redacted]")
            .field("q", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{paillier::DecryptionKey, utils::testing::init_testing};

    use super::{AuxInfoPrivate, AUXINFO_TAG};

    #[test]
    fn auxinfo_private_to_from_bytes_works() {
        let rng = &mut init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(rng).unwrap();
        let private_aux_info = AuxInfoPrivate { decryption_key };

        let bytes = private_aux_info.clone().into_bytes();
        let reconstructed = AuxInfoPrivate::try_from_bytes(bytes);

        assert!(reconstructed.is_ok());
        assert_eq!(reconstructed.unwrap(), private_aux_info);
    }

    #[test]
    fn deserialized_auxinfo_private_tag_must_be_correct() {
        let rng = &mut init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(rng).unwrap();
        let private_aux_info = AuxInfoPrivate { decryption_key };

        let bytes = private_aux_info.into_bytes();

        // Tag must have correct content
        let wrong_content_tag = b"TotallyFakeAux";
        let bad_bytes = [wrong_content_tag.as_slice(), &bytes[AUXINFO_TAG.len()..]].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bad_bytes).is_err());

        // Tag must be correct length
        let short_tag = &AUXINFO_TAG[..5];
        let bad_bytes = [short_tag, &bytes[AUXINFO_TAG.len()..]].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bad_bytes).is_err());

        let bad_bytes = [AUXINFO_TAG, b"NICE_TAG!", &bytes[AUXINFO_TAG.len()..]].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bad_bytes).is_err());

        // Normal serialization works
        let bytes = [AUXINFO_TAG, &bytes[AUXINFO_TAG.len()..]].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bytes).is_ok());
    }

    #[test]
    fn deserialized_auxinfo_length_field_must_be_correct() {
        let rng = &mut init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(rng).unwrap();
        let key_bytes = decryption_key.into_bytes();

        // Must specify the length.
        let no_len_bytes = [AUXINFO_TAG, &key_bytes].concat();
        assert!(AuxInfoPrivate::try_from_bytes(no_len_bytes).is_err());

        // Length must be little endian
        let key_len = key_bytes.len().to_be_bytes();
        let be_bytes = [AUXINFO_TAG, &key_len, &key_bytes].concat();
        assert!(AuxInfoPrivate::try_from_bytes(be_bytes).is_err());

        // Length must be correct (not too long, not too short)
        let too_short = (key_bytes.len() - 5).to_le_bytes();
        let bad_bytes = [AUXINFO_TAG, &too_short, &key_bytes].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bad_bytes).is_err());

        let too_long = (key_bytes.len() + 5).to_le_bytes();
        let bad_bytes = [AUXINFO_TAG, &too_long, &key_bytes].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bad_bytes).is_err());

        // Correct length works :)
        let key_len = key_bytes.len().to_le_bytes();
        let bytes = [AUXINFO_TAG, &key_len, &key_bytes].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bytes).is_ok());
    }

    #[test]
    fn deserialized_auxinfo_requires_all_fields() {
        let bytes = b"AUX";
        assert!(AuxInfoPrivate::try_from_bytes(bytes.to_vec()).is_err());
        assert!(AuxInfoPrivate::try_from_bytes(AUXINFO_TAG.to_vec()).is_err());

        let key_len: usize = 2048;
        let bytes = [AUXINFO_TAG, &key_len.to_le_bytes()].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bytes.to_vec()).is_err());

        let key_len: usize = 0;
        let bytes = [AUXINFO_TAG, &key_len.to_le_bytes()].concat();
        assert!(AuxInfoPrivate::try_from_bytes(bytes.to_vec()).is_err());
    }
}
