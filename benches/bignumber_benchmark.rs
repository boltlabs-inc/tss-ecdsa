use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use glass_pumpkin::safe_prime;
use hex::ToHex;
use libpaillier::unknown_order::BigNumber;
use num_bigint::BigInt;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use rug::{Complete, Integer};

const PRIME_SIZE: usize = 1024;

criterion_group! {
    name = slow_primegen;
    config = Criterion::default().sample_size(10);
    targets = compare_prime_gen
}
criterion_group!(benches, compare_modpow);
criterion_main!(benches, slow_primegen);

fn compare_prime_gen(c: &mut Criterion) {
    println!("⚠️ gnu prime generation benchmark will only be correct if the libpaillier library has feature \"gnu\" enabled!");
    c.bench_function("openssl prime gen", |b| b.iter(ossl_prime_gen));
    c.bench_function("bigint prime gen", |b| b.iter(bigint_prime_gen));
    c.bench_function("gnu prime gen", |b| b.iter(gnu_prime_gen));
}

/// Use the openssl wrapper directly.
fn ossl_prime_gen() {
    let mut prime = BigNum::new().unwrap();
    prime
        .generate_prime(PRIME_SIZE as i32, true, None, None)
        .unwrap();
}

/// The Rust num_bigint crate doesn't have safe-prime generation methods
/// directly. Instead, use the glass pumpkin crate to create a `BigUint`.
fn bigint_prime_gen() {
    let mut rng = rand::thread_rng();
    safe_prime::from_rng(PRIME_SIZE, &mut rng).unwrap();
}

/// The GNU prime generation method is hard to use, so assume that the BigNumber
/// crate is configured to use gnu.
fn gnu_prime_gen() {
    BigNumber::safe_prime(PRIME_SIZE);
}

/// Modular exponentiation is a common operation in the protocol. A typical
/// usage is in Paillier encryption. With our parameter settings, this would be
/// a `b^a mod M`, where:
/// - b: the base is either from Z*_N or is 1+N, where N is a 2048-bit modulus.
/// - a: the exponent is either a message in Z_N or N itself (so, 2048 bits).
/// - M: the modulus is the square of the 2048-bit modulus N
///
/// Setup allows us to not count the time to initiate variables in the
/// benchmarking.
fn compare_modpow(c: &mut Criterion) {
    let mut base_rng = rand::thread_rng();
    let mut exp_rng = rand::thread_rng();

    // Get a hex-encoded element in Z*_N, where N is the output of `modulus()`.
    let mut base = || -> String {
        let n = BigNumber::from_slice(hex::decode(modulus_string()).unwrap());
        let z_star: BigNumber = BigNumber::from_rng(&(n - 1), &mut base_rng) + 1;
        z_star.to_bytes().encode_hex()
    };

    // Get a hex-encoded element in Z_N, where N is the output of `modulus()`.
    let mut exponent = || -> String {
        let n = BigNumber::from_slice(hex::decode(modulus_string()).unwrap());
        BigNumber::from_rng(&n, &mut exp_rng)
            .to_bytes()
            .encode_hex()
    };

    let modulus = &to_ossl(modulus_string()) * &to_ossl(modulus_string());
    c.bench_function("openssl modpow", |b| {
        b.iter_batched(
            || (to_ossl(base()), to_ossl(exponent())),
            |(base, exp)| ossl_modpow(base, exp, &modulus),
            BatchSize::SmallInput,
        )
    });

    let modulus = to_bigint(modulus_string()) * to_bigint(modulus_string());
    c.bench_function("bigint modpow", |b| {
        b.iter_batched(
            || (to_bigint(base()), to_bigint(exponent())),
            |(base, exponent)| bigint_modpow(base, exponent, &modulus),
            BatchSize::SmallInput,
        )
    });

    let modulus = to_gmp(modulus_string()) * to_gmp(modulus_string());
    c.bench_function("gmp modpow", |b| {
        b.iter_batched(
            || (to_gmp(base()), to_gmp(exponent())),
            |(base, exponent)| gmp_modpow(base, exponent, &modulus),
            BatchSize::SmallInput,
        )
    });
}

/// Get a hex string of a 2048-bit product of two safe primes.
fn modulus_string() -> String {
    "aae7348ef0b743475d5a64a4c27e0c717771a40da32eaabf729d5d3fbb794ebf3bbb5096474e8ca2f0d64bb0481d855f12aad504e94e39e6fc4c1a2b7a4c42649fb7b2a02d245713c289f287b6dda8396d2a8f8f3e02d7ee14b437e3ee5e450becf6f8f38c7c5a5cfffc4de26028f44ebaf63c8a78dd7045d0473fac663e66a0552ca6edc94153793069a5a53e39a6ac49bb08b74fa2e0ba83a6546877e745daf8eb30b87281c8c9ceecfcf3cd271eb6d000567fecada07729a296e9ec078c711f16f5f31c679b60e4f9d78a385b679cbcc6e93d52f656356b9d293d4e7b1f7c80e0444d18a2c150d5a358c7a01ca413d1a0471c737257d84d213d91ab24bd4d"
        .into()
    /*
       [
           "C3538E1FE5ED23EC1AFFB9A1FC9F8891EC5CD38062393A94789718B81CF6A1D1FE61B28197525D51C1767749D3488132239CCDCC3383DD9B050AC9E544964B8EA3895149369D4CA6226BD4AE618EB746D4EF4A7477EE08CBA9BE73E7887261678D27519BEE2237E128591DAD4E2EAAE43CF0802E3DDE681BAF7F78EC6BC15393",
           "DFFD80ACE4F8800EC5C4544855DEE54317BCDFF3324BA93BFAA95AF94F8A7922E553C6D0CE1E23A0C05702047F687379208496B66023E6BD4E547CD0607D2B080C5C75C133DD16E93315E28AAD0438737C53D23C78D1CBED65C0B105EE81999589CA1A61252EF47E48E550D920B3E24DAB6E5E6D0286298BF3910EF31335F79F"
       ]
           .iter()
           .map(|s| BigNumber::from_slice(hex::decode(s).unwrap()))
           .reduce(|p1, p2| p1 * p2)
           .unwrap()
           .to_bytes()
           .encode_hex()
    */
}

fn to_ossl(val: String) -> BigNum {
    BigNum::from_hex_str(&val).unwrap()
}

/// Assumes a positive exponent.
fn ossl_modpow(base: BigNum, exponent: BigNum, modulus: &BigNum) {
    let mut ctx = BigNumContext::new().unwrap();
    let mut bn = BigNum::new().unwrap();
    BigNumRef::mod_exp(&mut bn, &base, &exponent, modulus, &mut ctx).unwrap();
}

fn to_bigint(val: String) -> BigInt {
    BigInt::from_bytes_be(num_bigint::Sign::Plus, val.as_bytes())
}

fn bigint_modpow(base: BigInt, exponent: BigInt, modulus: &BigInt) {
    base.modpow(&exponent, modulus);
}

fn to_gmp(val: String) -> Integer {
    Integer::from_digits(
        hex::decode(val).unwrap().as_ref(),
        rug::integer::Order::MsfBe,
    )
}

fn gmp_modpow(base: Integer, exponent: Integer, modulus: &Integer) {
    base.secure_pow_mod_ref(&exponent, modulus).complete();
}
