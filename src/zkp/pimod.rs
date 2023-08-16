// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a zero-knowledge proof that the modulus `N` is a Paillier-Blum
//! modulus meaning that the `gcd (N, phi(N)) = 1` where `phi` is the Euler's
//! totient function and `N = pq` where `p`, `q` is congruent to `3 mod 4`.
//! The proof is defined in Figure 16 of CGGMP[^cite].
//! The protocol is a combination (and simplification) of van de Graaf and
//! Peralta[^cite1] and Goldberg et al[^cite2].
//!
//! This implementation uses a standard Fiat-Shamir transformation to make the
//! proof non-interactive.
//!
//! [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
//! [EPrint archive, 2021](https://eprint.iacr.org/2021/060.pdf).
//!
//! [^cite1]: J. van de Graaf and R. Peralta. A simple and secure way to show the validity of your public key. In
//! Advances in Cryptology - CRYPTO ’87, A Conference on the Theory and
//! Applications of Cryptographic Techniques, Santa Barbara, California, USA,
//! August 16-20, 1987, Proceedings, pages 128–134, 1987.
//!
//! [^cite2]: Sharon
//! Goldberg, Leonid Reyzin, Omar Sagga, and Foteini Baldimtsi. Efficient
//! noninteractive certification of RSA moduli and beyond. In Advances in
//! Cryptology - ASIACRYPT 2019 - 25th International Conference on the Theory
//! and Application of Cryptology and Information Security, Kobe, Japan,
//! December 8-12, 2019, Proceedings, Part III, pages 700–727, 2019.

use crate::{
    errors::*,
    utils::*,
    zkp::{Proof, ProofContext},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, fmt::Debug};
use tracing::error;
use zeroize::ZeroizeOnDrop;

// Soundness parameter lambda
static LAMBDA: usize = crate::parameters::SOUNDNESS_PARAMETER;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiModProof {
    random_jacobi_one: BigNumber,
    // (x, a, b, z),
    elements: Vec<PiModProofElements>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiModProofElements {
    /// Fourth root of the constraint linking the `random_jacobi_one` request
    /// with the challenge (`x_i` in the paper).
    fourth_root: BigNumber,
    /// Determining the sign of the root (`a_i` in the paper).
    sign_exponent: usize,
    /// Satifies the jacobi symbol (`b_i` in the paper).
    jacobi_exponent: usize,
    /// Function of the challenge and the secret input (`z_i` in the paper).
    challenge_secret_link: BigNumber,
    /// Challenge value, chosen via fiat-Shamir (`y_i` in the paper).
    challenge: BigNumber,
}

#[derive(Serialize)]
pub(crate) struct CommonInput {
    modulus: BigNumber,
}

impl CommonInput {
    pub(crate) fn new(modulus: &BigNumber) -> Self {
        Self {
            modulus: modulus.clone(),
        }
    }
}

#[derive(ZeroizeOnDrop)]
pub(crate) struct ProverSecret {
    p: BigNumber,
    q: BigNumber,
}

impl Debug for ProverSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("pimod::PiModSecret")
            .field("p", &"[redacted]")
            .field("q", &"[redacted]")
            .finish()
    }
}

impl ProverSecret {
    pub(crate) fn new(p: &BigNumber, q: &BigNumber) -> Self {
        Self {
            p: p.clone(),
            q: q.clone(),
        }
    }
}

impl Proof for PiModProof {
    type CommonInput = CommonInput;
    type ProverSecret = ProverSecret;
    /// Generated by the prover, requires public input N and secrets (p,q)
    /// Prover generates a random w in Z_N of Jacobi symbol -1
    #[allow(clippy::many_single_char_names)]
    #[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        // Step 1: Pick a random w in [1, N) that has a Jacobi symbol of -1
        let mut w = random_positive_bn(rng, &input.modulus);
        while jacobi(&w, &input.modulus) != -1 {
            w = random_positive_bn(rng, &input.modulus);
        }

        Self::fill_transcript(transcript, context, input, &w)?;

        let elements = (0..LAMBDA)
            .map(|_| {
                let y = positive_challenge_from_transcript(transcript, &input.modulus)?;
                let (a, b, mut x) = y_prime_combinations(&w, &y, &secret.p, &secret.q)?;

                let phi_n = (&secret.p - 1) * (&secret.q - 1);
                let exp = input.modulus.invert(&phi_n).ok_or_else(|| {
                    error!("Could not invert N");
                    InternalError::InternalInvariantFailed
                })?;
                let z = modpow(&y, &exp, &input.modulus);
                let fourth_root_y = x.pop().ok_or_else(|| {
                    error!("Expected to get a fourth root, but did not.");
                    InternalError::InternalInvariantFailed
                });
                Ok(PiModProofElements {
                    fourth_root: fourth_root_y?,
                    sign_exponent: a,
                    jacobi_exponent: b,
                    challenge_secret_link: z,
                    challenge: y,
                })
            })
            .collect::<Result<Vec<PiModProofElements>>>()?;

        let proof = Self {
            random_jacobi_one: w,
            elements,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
    fn verify(
        &self,
        input: &Self::CommonInput,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        // Verify that proof is sound -- it must have exactly LAMBDA elements
        match self.elements.len().cmp(&LAMBDA) {
            Ordering::Less => {
                error!(
                    "PiMod proof is not sound: has {} elements, expected {}",
                    self.elements.len(),
                    LAMBDA,
                );
                return Err(InternalError::ProtocolError);
            }
            Ordering::Greater => {
                error!(
                    "PiMod proof has too many elements: has {}, expected {}",
                    self.elements.len(),
                    LAMBDA
                );
                return Err(InternalError::ProtocolError);
            }
            Ordering::Equal => {}
        }

        // Verify that N is an odd composite number
        if &input.modulus % BigNumber::from(2u64) == BigNumber::zero() {
            error!("N is even");
            return Err(InternalError::ProtocolError);
        }

        if input.modulus.is_prime() {
            error!("N is not composite");
            return Err(InternalError::ProtocolError);
        }
        Self::fill_transcript(transcript, context, input, &self.random_jacobi_one)?;

        for elements in &self.elements {
            // First, check that y came from Fiat-Shamir transcript
            let y = positive_challenge_from_transcript(transcript, &input.modulus)?;
            if y != elements.challenge {
                error!("y does not match Fiat-Shamir challenge");
                return Err(InternalError::ProtocolError);
            }

            let y_candidate = modpow(
                &elements.challenge_secret_link,
                &input.modulus,
                &input.modulus,
            );
            if elements.challenge != y_candidate {
                error!("z^N != y (mod N)");
                return Err(InternalError::ProtocolError);
            }

            if elements.sign_exponent != 0 && elements.sign_exponent != 1 {
                error!("a not in {{0,1}}");
                return Err(InternalError::ProtocolError);
            }

            if elements.jacobi_exponent != 0 && elements.jacobi_exponent != 1 {
                error!("b not in {{0,1}}");
                return Err(InternalError::ProtocolError);
            }

            let y_prime = y_prime_from_y(
                &elements.challenge,
                &self.random_jacobi_one,
                elements.sign_exponent,
                elements.jacobi_exponent,
                &input.modulus,
            );
            if modpow(
                &elements.fourth_root,
                &BigNumber::from(4u64),
                &input.modulus,
            ) != y_prime
            {
                error!("x^4 != y' (mod N)");
                return Err(InternalError::ProtocolError);
            }
        }

        Ok(())
    }
}

impl PiModProof {
    fn fill_transcript(
        transcript: &mut Transcript,
        context: &impl ProofContext,
        input: &CommonInput,
        w: &BigNumber,
    ) -> Result<()> {
        transcript.append_message(b"PiMod ProofContext", &context.as_bytes()?);
        transcript.append_message(b"PiMod CommonInput", &serialize!(&input)?);
        transcript.append_message(b"w", &w.to_bytes());
        Ok(())
    }
}
// Compute regular mod
#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn bn_mod(n: &BigNumber, p: &BigNumber) -> BigNumber {
    n.modadd(&BigNumber::zero(), p)
}

// Denominator needs to be positive and odd
#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn jacobi(numerator: &BigNumber, denominator: &BigNumber) -> isize {
    let mut n = bn_mod(numerator, denominator);
    let mut k = denominator.clone();
    let mut t = 1;

    while n != BigNumber::zero() {
        while bn_mod(&n, &BigNumber::from(2)) == BigNumber::zero() {
            n /= 2;
            let r = bn_mod(&k, &BigNumber::from(8));
            if r == BigNumber::from(3) || r == BigNumber::from(5) {
                t *= -1;
            }
        }

        // (n, k) = (k, n), swap them
        std::mem::swap(&mut n, &mut k);

        if bn_mod(&n, &BigNumber::from(4)) == BigNumber::from(3)
            && bn_mod(&k, &BigNumber::from(4)) == BigNumber::from(3)
        {
            t *= -1;
        }
        n = bn_mod(&n, &k);
    }

    if k == BigNumber::one() {
        return t;
    }

    0
}

/// Finds the two x's such that x^2 = n (mod p), where p is a prime that is 3
/// (mod 4)
#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn square_roots_mod_prime(n: &BigNumber, p: &BigNumber) -> Option<(BigNumber, BigNumber)> {
    // Compute r = +- n^{p+1/4} (mod p)
    let r = modpow(n, &(&(p + 1) / 4), p);
    let neg_r = r.modneg(p);

    // Check that r and neg_r are such that r^2 = n (mod p) -- if not, then
    // there are no solutions

    if modpow(&r, &BigNumber::from(2), p) == bn_mod(n, p) {
        Some((r, neg_r))
    } else {
        None
    }
}

// Finds an (x,y) such that ax + by = 1, or returns error if gcd(a,b) != 1
#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn extended_euclidean(a: &BigNumber, b: &BigNumber) -> Result<(BigNumber, BigNumber)> {
    let result = a.extended_gcd(b);

    if result.gcd != BigNumber::one() {
        error!("Elements are not coprime");
        Err(InternalError::InternalInvariantFailed)?
    }

    Ok((result.x, result.y))
}

/// Compute the Chinese remainder theorem with two congruences.
///
/// That is, find the unique `x` such that:
/// - `x = a1 (mod p)`, and
/// - `x = a2 (mod q)`.
///
/// This returns an error if:
/// - `p` and `q` aren't co-prime;
/// - `a1` is not in the range `[0, p)`;
/// - `a2` is not in the range `[0, q)`.
#[allow(clippy::many_single_char_names)]
#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn chinese_remainder_theorem(
    a1: &BigNumber,
    a2: &BigNumber,
    p: &BigNumber,
    q: &BigNumber,
) -> Result<BigNumber> {
    let zero = &BigNumber::zero();
    if a1 >= p || a1 < zero || a2 >= q || a2 < zero {
        error!("One or more of the integer inputs to the Chinese remainder theorem were outside the expected range");
        Err(InternalError::InternalInvariantFailed)?
    }
    let (z, w) = extended_euclidean(p, q)?;
    let x = a1 * w * q + a2 * z * p;
    Ok(bn_mod(&x, &(p * q)))
}

/// Finds the four x's such that x^2 = n (mod pq), where p,q are primes that are
/// 3 (mod 4)
#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn square_roots_mod_composite(
    n: &BigNumber,
    p: &BigNumber,
    q: &BigNumber,
) -> Result<Option<[BigNumber; 4]>> {
    let (y1, y2) = match square_roots_mod_prime(n, p) {
        Some(roots) => roots,
        None => return Ok(None),
    };
    let (z1, z2) = match square_roots_mod_prime(n, q) {
        Some(roots) => roots,
        None => return Ok(None),
    };

    let x1 = chinese_remainder_theorem(&y1, &z1, p, q)?;
    let x2 = chinese_remainder_theorem(&y1, &z2, p, q)?;
    let x3 = chinese_remainder_theorem(&y2, &z1, p, q)?;
    let x4 = chinese_remainder_theorem(&y2, &z2, p, q)?;

    Ok(Some([x1, x2, x3, x4]))
}

#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn fourth_roots_mod_composite(
    n: &BigNumber,
    p: &BigNumber,
    q: &BigNumber,
) -> Result<Option<Vec<BigNumber>>> {
    let mut fourth_roots = vec![];

    let square_roots = match square_roots_mod_composite(n, p, q)? {
        None => return Ok(None),
        Some(roots) => roots,
    };

    // Note: could iter-ize this
    for root in square_roots {
        match square_roots_mod_composite(&root, p, q)? {
            Some(res) => {
                for y in res {
                    fourth_roots.push(y);
                }
            }
            None => {
                continue;
            }
        }
    }
    Ok(Some(fourth_roots))
}

/// Compute y' = (-1)^a * w^b * y (mod N)
#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn y_prime_from_y(y: &BigNumber, w: &BigNumber, a: usize, b: usize, N: &BigNumber) -> BigNumber {
    let mut y_prime = y.clone();

    if b == 1 {
        y_prime = y_prime.modmul(w, N);
    }

    if a == 1 {
        y_prime = y_prime.modneg(N);
    }

    y_prime
}

/// Finds unique a,b in {0,1} such that, for y' = (-1)^a * w^b * y, there is an
/// x such that x^4 = y (mod pq)
/// In practice, it is sufficient to use only the first element of the
/// [`Vec<BigNumber>`] as the third output since it is the only part that goes
/// into the proof.
#[cfg_attr(feature = "flame_it", flame("PaillierBlumModulusProof"))]
fn y_prime_combinations(
    w: &BigNumber,
    y: &BigNumber,
    p: &BigNumber,
    q: &BigNumber,
) -> Result<(usize, usize, Vec<BigNumber>)> {
    let N = p * q;

    let mut ret = vec![];

    let mut has_fourth_roots = 0;
    let mut success_a = 0;
    let mut success_b = 0;

    for a in 0..2 {
        for b in 0..2 {
            let y_prime = y_prime_from_y(y, w, a, b, &N);
            match fourth_roots_mod_composite(&y_prime, p, q)? {
                Some(values) => {
                    has_fourth_roots += 1;
                    success_a = a;
                    success_b = b;
                    ret.extend_from_slice(&values);
                }
                None => {
                    continue;
                }
            }
        }
    }

    if has_fourth_roots != 1 {
        error!(
            "Could not find uniqueness for fourth roots combination in Paillier-Blum modulus proof"
        );
        return Err(InternalError::InternalInvariantFailed);
    }

    Ok((success_a, success_b, ret))
}

#[cfg(test)]
mod tests {
    use rand::random;

    use super::*;
    use crate::{
        paillier::{prime_gen, DecryptionKey},
        parameters::SOUNDNESS_PARAMETER,
        utils::testing::init_testing,
        zkp::BadContext,
    };

    fn transcript() -> Transcript {
        Transcript::new(b"PiMod Test")
    }

    #[test]
    fn test_jacobi() {
        let mut rng = init_testing();
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let N = &p * &q;

        for _ in 0..100 {
            let a = BigNumber::from_rng(&N, &mut rng);

            let a_p = jacobi(&a, &p);
            let a_q = jacobi(&a, &q);

            // Verify that a^{p-1/2} == a_p (mod p)
            assert_eq!(
                bn_mod(&BigNumber::from(a_p), &p),
                modpow(&a, &(&(&p - 1) / 2), &p)
            );

            // Verify that a^{q-1/2} == a_q (mod q)
            assert_eq!(
                bn_mod(&BigNumber::from(a_q), &q),
                modpow(&a, &(&(&q - 1) / 2), &q)
            );

            // Verify that (a/n) = (a/p) * (a/q)
            let a_n = jacobi(&a, &N);
            assert_eq!(a_n, a_p * a_q);
        }
    }

    #[test]
    fn test_square_roots_mod_prime() {
        let mut rng = init_testing();
        let p = prime_gen::try_get_prime_from_pool_insecure(&mut rng).unwrap();

        for _ in 0..100 {
            let a = BigNumber::from_rng(&p, &mut rng);
            let a_p = jacobi(&a, &p);

            let roots = square_roots_mod_prime(&a, &p);
            match roots {
                Some((r1, r2)) => {
                    assert_eq!(a_p, 1);
                    assert_eq!(modpow(&r1, &BigNumber::from(2), &p), a);
                    assert_eq!(modpow(&r2, &BigNumber::from(2), &p), a);
                }
                None => {
                    assert_ne!(a_p, 1);
                }
            }
        }
    }

    #[test]
    fn test_square_roots_mod_composite() {
        let mut rng = init_testing();
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let N = &p * &q;

        // Loop until we've confirmed enough successes
        let mut success = 0;
        loop {
            if success == 10 {
                return;
            }
            let a = BigNumber::from_rng(&N, &mut rng);
            let a_n = jacobi(&a, &N);

            // This shouldn't throw an error
            let roots = square_roots_mod_composite(&a, &p, &q).unwrap();

            // It's ok if it doesn't give a fourth root, though
            match roots {
                Some(xs) => {
                    assert_eq!(a_n, 1);
                    for x in xs {
                        assert_eq!(modpow(&x, &BigNumber::from(2), &N), a);
                    }
                    success += 1;
                }
                None => {
                    continue;
                }
            }
        }
    }

    #[test]
    fn modulus_should_have_prime_factors() -> Result<()> {
        let mut rng = init_testing();
        let (_, _p, q) = DecryptionKey::new(&mut rng).unwrap();
        let one: BigNumber = BigNumber::from(1);
        let modulus = one.clone() * q.clone();
        let input = CommonInput { modulus };
        let secret = ProverSecret { p: one, q };
        let proof = match PiModProof::prove(&input, &secret, &(), &mut transcript(), &mut rng) {
            Ok(proof) => proof,
            Err(_) => return Err(InternalError::InternalInvariantFailed),
        };
        assert!(proof.verify(&input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn test_fourth_roots_mod_composite() {
        let mut rng = init_testing();
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        let N = &p * &q;

        // Loop until we've confirmed enough successes
        let mut success = 0;
        loop {
            if success == 10 {
                return;
            }
            let a = BigNumber::from_rng(&N, &mut rng);
            let a_n = jacobi(&a, &N);

            let roots = fourth_roots_mod_composite(&a, &p, &q).unwrap();
            match roots {
                Some(xs) => {
                    assert_eq!(a_n, 1);
                    for x in xs {
                        assert_eq!(modpow(&x, &BigNumber::from(4), &N), a);
                    }
                    success += 1;
                }
                None => {
                    continue;
                }
            }
        }
    }

    #[test]
    fn chinese_remainder_theorem_works() {
        let mut rng = init_testing();
        // This guarantees p and q are coprime and not equal.
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        assert!(p != q);

        for _ in 0..100 {
            // This method guarantees a1 and a2 are smaller than their moduli.
            let a1 = BigNumber::from_rng(&p, &mut rng);
            let a2 = BigNumber::from_rng(&q, &mut rng);

            let x = chinese_remainder_theorem(&a1, &a2, &p, &q).unwrap();

            assert_eq!(bn_mod(&x, &p), a1);
            assert_eq!(bn_mod(&x, &q), a2);
            assert!(x < &p * &q);
        }
    }

    #[test]
    fn chinese_remainder_theorem_integers_must_be_in_range() {
        let mut rng = init_testing();

        // This guarantees p and q are coprime and not equal.
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        assert!(p != q);

        // a1 = p
        let a1 = &p;
        let a2 = BigNumber::from_rng(&q, &mut rng);
        assert!(chinese_remainder_theorem(a1, &a2, &p, &q).is_err());

        // a1 > p
        let a1 = a1 + BigNumber::one();
        assert!(chinese_remainder_theorem(&a1, &a2, &p, &q).is_err());

        // a1 < 0
        let a1 = -BigNumber::from_rng(&p, &mut rng);
        assert!(chinese_remainder_theorem(&a1, &a2, &p, &q).is_err());

        // a2 = q
        let a1 = BigNumber::from_rng(&p, &mut rng);
        let a2 = &q;
        assert!(chinese_remainder_theorem(&a1, a2, &p, &q).is_err());

        // a2 > q
        let a2 = a2 + BigNumber::one();
        assert!(chinese_remainder_theorem(&a1, &a2, &p, &q).is_err());

        // a2 < 0
        let a2 = -BigNumber::from_rng(&q, &mut rng);
        assert!(chinese_remainder_theorem(&a1, &a2, &p, &q).is_err());
    }

    #[test]
    fn chinese_remainder_theorem_moduli_must_be_coprime() {
        let mut rng = init_testing();

        // This guarantees p and q are coprime and not equal.
        let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(&mut rng).unwrap();
        assert!(p != q);

        // choose small a1, a2 so that they work for all our tests
        let smaller_prime = if p < q { &p } else { &q };
        let a1 = BigNumber::from_rng(smaller_prime, &mut rng);
        let a2 = BigNumber::from_rng(smaller_prime, &mut rng);

        // p = q
        let bad_q = &p;
        assert!(chinese_remainder_theorem(&a1, &a1, &p, bad_q).is_err());

        // p = kq for some k
        let mult_p = &q + &q;
        assert!(chinese_remainder_theorem(&a1, &a1, &mult_p, &q).is_err());

        // q = kp for some k
        let mult_q = &p + &p;
        assert!(chinese_remainder_theorem(&a1, &a2, &p, &mult_q).is_err());

        assert!(chinese_remainder_theorem(&a1, &a2, &p, &q).is_ok());
    }

    fn random_big_number<R: RngCore + CryptoRng>(rng: &mut R) -> BigNumber {
        let x_len = rng.next_u64() as u16;
        let mut buf_x = (0..x_len).map(|_| 0u8).collect::<Vec<u8>>();
        rng.fill_bytes(&mut buf_x);
        BigNumber::from_slice(buf_x.as_slice())
    }

    fn random_pbmpe<R: RngCore + CryptoRng>(rng: &mut R) -> PiModProofElements {
        let x = random_big_number(rng);
        let y = random_big_number(rng);
        let z = random_big_number(rng);

        let a = rng.next_u64() as u16;
        let b = rng.next_u64() as u16;

        PiModProofElements {
            fourth_root: x,
            sign_exponent: a as usize,
            jacobi_exponent: b as usize,
            challenge: y,
            challenge_secret_link: z,
        }
    }

    #[test]
    fn test_blum_modulus_proof_elements_roundtrip() {
        let mut rng = init_testing();
        let pbelement = random_pbmpe(&mut rng);
        let buf = bincode::serialize(&pbelement).unwrap();
        let roundtrip_pbelement: PiModProofElements = bincode::deserialize(&buf).unwrap();
        assert_eq!(buf, bincode::serialize(&roundtrip_pbelement).unwrap());
    }

    #[test]
    fn test_blum_modulus_roundtrip() {
        let mut rng = init_testing();

        let w = random_big_number(&mut rng);
        let num_elements = rng.next_u64() as u8;
        let elements = (0..num_elements)
            .map(|_| random_pbmpe(&mut rng))
            .collect::<Vec<PiModProofElements>>();

        let pbmp = PiModProof {
            random_jacobi_one: w,
            elements,
        };
        let buf = bincode::serialize(&pbmp).unwrap();
        let roundtrip_pbmp: PiModProof = bincode::deserialize(&buf).unwrap();
        assert_eq!(buf, bincode::serialize(&roundtrip_pbmp).unwrap());
    }

    fn random_pimod_proof<R: CryptoRng + RngCore>(rng: &mut R) -> (PiModProof, CommonInput) {
        let (decryption_key, p, q) = DecryptionKey::new(rng).unwrap();

        let input = CommonInput {
            modulus: decryption_key.encryption_key().modulus().to_owned(),
        };
        let secret = ProverSecret { p, q };

        let proof_result = PiModProof::prove(&input, &secret, &(), &mut transcript(), rng);
        assert!(proof_result.is_ok());
        (proof_result.unwrap(), input)
    }

    #[test]
    fn secret_input_should_be_correct() -> Result<()> {
        let mut rng = init_testing();
        let (_, p, q) = DecryptionKey::new(&mut rng).unwrap();
        let (new_decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let input = CommonInput {
            modulus: new_decryption_key.encryption_key().modulus().to_owned(),
        };
        let bad_secret = ProverSecret { p, q };
        let proof = PiModProof::prove(&input, &bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(proof.verify(&input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn challenges_must_be_derived_from_transcript() -> Result<()> {
        let mut rng = init_testing();
        let (mut bad_proof, input) = random_pimod_proof(&mut rng);
        let new_challenge = random_positive_bn(&mut rng, &k256_order());
        if let Some(first_element) = bad_proof.elements.get_mut(0) {
            first_element.challenge = new_challenge;
        } else {
            panic!("No element found");
        }
        assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn commitment_must_be_correct() -> Result<()> {
        let mut rng = init_testing();
        let (mut bad_proof, input) = random_pimod_proof(&mut rng);
        bad_proof.random_jacobi_one = random_positive_bn(&mut rng, &k256_order());
        assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn responses_must_be_correct() -> Result<()> {
        let mut rng = init_testing();
        let (proof, input) = random_pimod_proof(&mut rng);
        let new_challenge_secret_link = random_positive_bn(&mut rng, &k256_order());
        let mut bad_proof = proof.clone();
        if let Some(first_element) = bad_proof.elements.get_mut(0) {
            first_element.challenge_secret_link = new_challenge_secret_link;
        } else {
            panic!("No element found");
        }
        assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        let mut bad_proof = proof.clone();
        let new_sign_exponent: usize = random();
        if let Some(first_element) = bad_proof.elements.get_mut(0) {
            first_element.sign_exponent = new_sign_exponent;
        } else {
            panic!("No element found");
        }
        assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        let mut bad_proof = proof.clone();
        let new_jacobi_exponent: usize = random();
        if let Some(first_element) = bad_proof.elements.get_mut(0) {
            first_element.sign_exponent = new_jacobi_exponent;
        } else {
            panic!("No element found");
        }
        assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        let new_fourth_root = random_positive_bn(&mut rng, &k256_order());
        let mut bad_proof = proof.clone();
        if let Some(first_element) = bad_proof.elements.get_mut(0) {
            first_element.fourth_root = new_fourth_root;
        } else {
            panic!("No element found");
        }
        assert!(bad_proof.verify(&input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn common_input_must_be_same_for_proving_and_verifying() -> Result<()> {
        let mut rng = init_testing();
        let random_bn = random_positive_bn(&mut rng, &k256_order());
        let (proof, _) = random_pimod_proof(&mut rng);
        let bad_input = CommonInput::new(&random_bn);
        assert!(proof.verify(&bad_input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn pimod_proof_verifies() {
        let mut rng = init_testing();
        let (proof, input) = random_pimod_proof(&mut rng);
        assert!(proof.verify(&input, &(), &mut transcript()).is_ok());
    }

    #[test]
    fn pimod_proof_context_must_be_correct() -> Result<()> {
        let mut rng = init_testing();
        let context = BadContext {};
        let (proof, input) = random_pimod_proof(&mut rng);
        let result = proof.verify(&input, &context, &mut transcript());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn pimod_proof_requires_correct_number_of_elements_for_soundness() {
        let mut rng = init_testing();

        let transform = |proof: &PiModProof| {
            // Remove iterations from the proof
            let short_proof = PiModProof {
                random_jacobi_one: proof.random_jacobi_one.clone(),
                elements: proof.elements[..SOUNDNESS_PARAMETER - 1].into(),
            };

            // Add elements to the proof. Not sure if this is actually a problem, but we'll
            // stick to the spec for now.
            let long_proof = PiModProof {
                random_jacobi_one: proof.random_jacobi_one.clone(),
                elements: proof
                    .elements
                    .clone()
                    .into_iter()
                    .cycle()
                    .take(SOUNDNESS_PARAMETER * 2)
                    .collect(),
            };

            (short_proof, long_proof)
        };

        // Make un-sound a proof generated with the standard API
        let (proof, input) = random_pimod_proof(&mut rng);
        let (short_proof, long_proof) = transform(&proof);

        assert!(short_proof.verify(&input, &(), &mut transcript()).is_err());
        assert!(long_proof.verify(&input, &(), &mut transcript()).is_err());
        assert!(proof.verify(&input, &(), &mut transcript()).is_ok());
    }
}
