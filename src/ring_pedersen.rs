// Copyright (c) 2023 Bolt Labs, Inc.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A (verifiable) ring-Pedersen commitment scheme.
//!
//! This implements the ring-Pedersen commitment scheme as specified in Definition 1.3 of
//! <https://eprint.iacr.org/2021/060.pdf>. The verifiable variant includes a zero-knowledge proof
//! that the commitment scheme parameters were constructed correctly.

use crate::paillier::DecryptionKey;
use crate::{
    errors::Result,
    utils::{modpow, random_plusminus_scaled, random_positive_bn},
    zkp::{
        piprm::{PiPrmProof, PiPrmSecret},
        Proof,
    },
};
use bytemuck::TransparentWrapper;
use bytemuck_derive::TransparentWrapper;
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A commitment scheme based on a ring-variant of the Pedersen commitment scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RingPedersen {
    /// The RSA modulus, corresponding to `N` in the paper.
    modulus: BigNumber,
    /// Ring-Pedersen parameter `s`.
    s: BigNumber,
    /// Ring-Pedersen parameter `t`.
    t: BigNumber,
}

/// A [`RingPedersen`] commitment scheme alongside a zero knowledge proof that
/// the commitment scheme was constructed correctly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct VerifiedRingPedersen {
    /// The underlying commitment scheme.
    scheme: RingPedersen,
    /// The zero knowledge proof that validates the correctness of [`VerifiedRingPedersen::scheme`].
    proof: PiPrmProof,
}

/// A commitment produced by [`RingPedersen::commit`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Commitment(BigNumber);

impl Commitment {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

/// The randomness generated as part of [`RingPedersen::commit`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TransparentWrapper)]
#[repr(transparent)]
pub(crate) struct CommitmentRandomness(BigNumber);

impl CommitmentRandomness {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Masks randomness with `mask` and `challenge`.
    ///
    /// The output [`MaskedRandomness`] value is computed as `mask - challenge * value`.
    pub(crate) fn mask_neg(
        &self,
        mask: &CommitmentRandomness,
        challenge: &BigNumber,
    ) -> MaskedRandomness {
        MaskedRandomness(&mask.0 - challenge * &self.0)
    }

    /// Masks randomness with `mask` and `challenge`.
    ///
    /// The output [`MaskedRandomness`] value is computed as `mask + challenge * value`.
    pub(crate) fn mask(
        &self,
        mask: &CommitmentRandomness,
        challenge: &BigNumber,
    ) -> MaskedRandomness {
        MaskedRandomness(&mask.0 + challenge * &self.0)
    }

    /// Returns the randomness as a [`MaskedRandomness`].
    pub(crate) fn as_masked(&self) -> &MaskedRandomness {
        MaskedRandomness::wrap_ref(&self.0)
    }
}

/// The randomness generated as part of [`RingPedersen::commit`] and masked
/// by [`CommitmentRandomness::mask`] or [`CommitmentRandomness::mask_neg`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TransparentWrapper)]
#[repr(transparent)]
pub(crate) struct MaskedRandomness(BigNumber);

impl MaskedRandomness {
    /// (Re)masks value with `mask` and `challenge`.
    ///
    /// This runs the same computation as [`CommitmentRandomness::mask`], except
    /// this time on the already masked value.
    pub(crate) fn remask(
        &self,
        mask: &CommitmentRandomness,
        challenge: &BigNumber,
    ) -> MaskedRandomness {
        let randomness = CommitmentRandomness::wrap_ref(&self.0);
        randomness.mask(mask, challenge)
    }
}

impl VerifiedRingPedersen {
    /// Extracts a [`VerifiedRingPedersen`] object from a [`DecryptionKey`].
    ///
    /// In more detail, `sk` is used to derive a
    /// [`RingPedersen`] commitment scheme, alongside a zero knowledge proof [`PiPrmProof`]
    /// that the produced commitment scheme is validly constructed.
    pub(crate) fn extract(
        sk: &DecryptionKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let modulus = sk.modulus();
        let totient = sk.totient();
        let tau = random_positive_bn(rng, modulus);
        let lambda = random_positive_bn(rng, totient);
        let t = tau.modpow(&BigNumber::from(2), modulus);
        let s = t.modpow(&lambda, modulus);
        let scheme = RingPedersen {
            modulus: modulus.clone(),
            s,
            t,
        };
        let secrets = PiPrmSecret::new(lambda, totient.clone());
        let proof = PiPrmProof::prove(rng, &scheme, &secrets)?;
        Ok(Self { scheme, proof })
    }

    /// Verifies that the underlying [`RingPedersen`] commitment scheme was constructed correctly
    /// according to the associated [`PiPrmProof`].
    pub(crate) fn verify(&self) -> Result<()> {
        self.proof.verify(self.scheme())
    }

    /// Returns the underlying [`RingPedersen`] commitment scheme associated
    /// with this object.
    pub(crate) fn scheme(&self) -> &RingPedersen {
        &self.scheme
    }

    /// Generates a [`VerifiedRingPedersen`] object from a random number generator for testing purposes.
    #[cfg(test)]
    pub(crate) fn gen(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self> {
        let (sk, _, _) = DecryptionKey::new(rng)?;
        Self::extract(&sk, rng)
    }
}

impl RingPedersen {
    /// Returns the underlying modulus.
    pub(crate) fn modulus(&self) -> &BigNumber {
        &self.modulus
    }

    /// Returns the underlying `s` parameter.
    pub(crate) fn s(&self) -> &BigNumber {
        &self.s
    }

    /// Returns the underlying `t` parameter.
    pub(crate) fn t(&self) -> &BigNumber {
        &self.t
    }

    /// Constructs a [`RingPedersen`] object from its constituent parts for testing purposes.
    #[cfg(test)]
    pub(crate) fn from_parts(s: BigNumber, t: BigNumber, modulus: BigNumber) -> Self {
        Self { modulus, s, t }
    }

    /// Produces commitment randomness.
    ///
    /// The commitment randomness is sampled from `± 2^range * modulus * N`,
    /// where `N` is the [modulus](RingPedersen::modulus) of the commitment scheme.
    pub(crate) fn commitment_randomness(
        &self,
        range: usize,
        modulus: &BigNumber,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> CommitmentRandomness {
        let randomness = random_plusminus_scaled(rng, range, &(modulus * &self.modulus));
        CommitmentRandomness(randomness)
    }

    /// Produces a commitment to `value`.
    ///
    /// The commitment is computed as [`s`](RingPedersen::s)`^value` [`t`](RingPedersen::t)`^randomness mod N`,
    /// where `randomness` is sampled from `± 2^range * N` and
    /// `N` is the [modulus](RingPedersen::modulus) of the commitment scheme.
    pub(crate) fn commit(
        &self,
        value: &BigNumber,
        range: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (Commitment, CommitmentRandomness) {
        let randomness = self.commitment_randomness(range, &BigNumber::one(), rng);
        let com = self.reconstruct(value, randomness.as_masked());
        (com, randomness)
    }

    /// Reconstructs a commitment to `value` using [`MaskedRandomness`] `randomness`.
    ///
    /// The commitment is computed as in [`RingPedersen::commit`], except `randomness` is passed in
    /// instead of it being generated by the commitment process.
    pub(crate) fn reconstruct(
        &self,
        value: &BigNumber,
        randomness: &MaskedRandomness,
    ) -> Commitment {
        let a = modpow(&self.s, value, &self.modulus);
        let b = modpow(&self.t, &randomness.0, &self.modulus);
        Commitment(a.modmul(&b, &self.modulus))
    }

    /// Combines two commitments with exponent `e`.
    ///
    /// The resulting commitment is computed by `com0 * com1^e mod N`,
    /// where `N` is the [modulus](RingPedersen::modulus) of the commitment scheme.
    pub(crate) fn combine(
        &self,
        com0: &Commitment,
        com1: &Commitment,
        e: &BigNumber,
    ) -> Commitment {
        Commitment(
            com0.0
                .modmul(&modpow(&com1.0, e, &self.modulus), &self.modulus),
        )
    }

    /// Produces a commitment to `value` using [`Commitment`] `com`.
    ///
    /// In more detail, the following is computed: `com^value t^r mod N` where `r` falls
    /// in the range `± 2^range * modulus * N` and `N` is the [modulus](RingPedersen::modulus) of the
    /// commitment scheme.
    pub(crate) fn commit_with_commitment(
        &self,
        com: &Commitment,
        value: &BigNumber,
        range: usize,
        modulus: &BigNumber,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (Commitment, CommitmentRandomness) {
        let randomness = self.commitment_randomness(range, modulus, rng);
        let com = self.reconstruct_with_commitment(com, value, randomness.as_masked());
        (com, randomness)
    }

    /// Reconstructs a commitment to `value` using [`Commitment`] `com` and [`MaskedRandomness`]
    /// `randomness`.
    pub(crate) fn reconstruct_with_commitment(
        &self,
        com: &Commitment,
        value: &BigNumber,
        randomness: &MaskedRandomness,
    ) -> Commitment {
        Commitment(modpow(&com.0, value, &self.modulus).modmul(
            &modpow(&self.t, &randomness.0, &self.modulus),
            &self.modulus,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{get_test_rng, random_plusminus_by_size};

    use super::*;

    #[test]
    fn verified_ring_pedersen_generation_works() -> Result<()> {
        let mut rng = get_test_rng();
        let scheme = VerifiedRingPedersen::gen(&mut rng)?;
        assert!(scheme.verify().is_ok());
        Ok(())
    }

    #[test]
    fn mixing_verified_ring_pedersen_scheme_and_proof_fails() -> Result<()> {
        let mut rng = get_test_rng();
        // Mixing a proof from one scheme with another should fail.
        let scheme0 = VerifiedRingPedersen::gen(&mut rng)?;
        let scheme1 = VerifiedRingPedersen::gen(&mut rng)?;
        let scheme_mixed = VerifiedRingPedersen {
            scheme: scheme0.scheme,
            proof: scheme1.proof,
        };
        assert!(scheme_mixed.verify().is_err());
        Ok(())
    }

    #[test]
    fn ring_pedersen_commitments_work() -> Result<()> {
        let mut rng = get_test_rng();
        let scheme = VerifiedRingPedersen::gen(&mut rng)?;
        let value = random_plusminus_by_size(&mut rng, 256);
        let (c, r) = scheme.scheme().commit(&value, 256, &mut rng);
        let c_ = scheme.scheme().reconstruct(&value, r.as_masked());
        assert_eq!(c, c_);
        Ok(())
    }

    #[test]
    fn mixing_ring_pedersen_commitments_fails() -> Result<()> {
        let mut rng = get_test_rng();
        let scheme = VerifiedRingPedersen::gen(&mut rng)?;
        let value0 = random_plusminus_by_size(&mut rng, 256);
        let value1 = random_plusminus_by_size(&mut rng, 256);
        // This'll be true except with extremely small probability.
        assert_ne!(value0, value1);
        let (c0, r0) = scheme.scheme().commit(&value0, 256, &mut rng);
        let (c1, r1) = scheme.scheme().commit(&value1, 256, &mut rng);
        assert_ne!(c0, c1);
        assert_ne!(r0, r1);
        let c_invalid = scheme.scheme().reconstruct(&value0, r1.as_masked());
        assert_ne!(c_invalid, c0);
        assert_ne!(c_invalid, c1);
        let c_invalid = scheme.scheme().reconstruct(&value1, r0.as_masked());
        assert_ne!(c_invalid, c0);
        assert_ne!(c_invalid, c1);
        Ok(())
    }
}
