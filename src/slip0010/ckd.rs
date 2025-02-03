//! Utilities for Child Key Derivation (CKD) according to SLIP-0010.

use crate::{
    curve::{CurveTrait, ScalarTrait},
    errors::CallerError,
};
use generic_array::{
    typenum::{U32, U64},
    GenericArray,
};
use hmac::Mac;
use libpaillier::unknown_order::BigNumber;

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

const CURVE_NAME: &str = "Bitcoin seed";

/// Represents the input to the CKD function.
#[derive(Debug, Clone)]
pub struct CKDInput<C: CurveTrait> {
    private_key: Option<C::Scalar>,
    public_key: C,
    chain_code: [u8; 32],
    index: u32,
}

/// Represents the output of the CKD function.
#[derive(Debug, Clone)]
pub struct CKDOutput<C: CurveTrait> {
    /// The chain code, used to generate more child keys.
    pub chain_code: [u8; 32],
    /// If private_key for `CKDInput` is None, this is equal to a
    /// public shift value that should be applied to the public key
    /// and used as the shift in [`Input`](crate::sign::Input) to the
    /// non-interactive signing protocol.   
    /// If private_key for `CKDInput` is present, this is the full
    /// ECDSA private key
    pub private_key: C::Scalar,
}

/// Represents the input to the master key derivation function.
#[derive(Debug, Clone)]
pub struct MasterKeyInput {
    seed: Vec<u8>,
    curve: String,
}

impl MasterKeyInput {
    /// Create a new MasterKeyInput.
    pub fn new(seed: &[u8], curve: String) -> Result<Self, CallerError> {
        if curve != CURVE_NAME {
            Err(CallerError::WrongCurve)
        } else {
            Ok(Self {
                seed: seed.to_vec(),
                curve,
            })
        }
    }

    /// Derive master key from seed.
    pub fn derive_master_key<C: CurveTrait>(&self) -> CKDOutput<C> {
        let hmac = HmacSha512::new_from_slice(self.curve.as_bytes())
            .expect("this never fails: hmac can handle keys of any size");
        let mut i = hmac
            .clone()
            .chain_update(self.seed.clone())
            .finalize()
            .into_bytes();

        loop {
            let (i_left, i_right) = split_into_two_halfes(&i);
            if let Ok(private_key) = C::bn_to_scalar(&BigNumber::from_slice(i_left)) {
                let master_private_key = private_key;
                let master_public_key = C::GENERATOR.mul(&master_private_key);
                if master_public_key != C::IDENTITY {
                    return CKDOutput {
                        chain_code: (*i_right).into(),
                        private_key: C::bn_to_scalar(&BigNumber::from_slice(*i_left)).unwrap(),
                    };
                }
            }

            i = hmac.clone().chain_update(&i[..]).finalize().into_bytes();
        }
    }
}

impl<C: CurveTrait> CKDInput<C> {
    /// Create a new CKDInput.
    /// If the purpose is non-threshold key generation, the private key
    /// should be provided. If the purpose is for threshold key generation,
    /// the private key should be None.
    pub fn new(
        private_key: Option<C::Scalar>,
        public_key: C,
        chain_code: [u8; 32],
        index: u32,
    ) -> Result<Self, CallerError> {
        // index provided is for hardened child keys and
        // we cannot produce this in the threshold setting, fail
        if index >= 0x80000000 {
            Err(CallerError::WrongIndex)
        } else {
            Ok(Self {
                private_key,
                public_key,
                chain_code,
                index,
            })
        }
    }

    /// Get the chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Derives a shift for non-hardened child
    pub fn derive_public_shift(&self) -> CKDOutput<C> {
        let hmac = HmacSha512::new_from_slice(&self.chain_code)
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac
            .clone()
            .chain_update(self.public_key.to_bytes().as_slice())
            .chain_update(self.index.to_be_bytes())
            .finalize()
            .into_bytes();
        self.calculate_shift(&hmac, i)
    }

    fn calculate_shift(
        &self,
        hmac: &HmacSha512,
        mut i: hmac::digest::Output<HmacSha512>,
    ) -> CKDOutput<C> {
        loop {
            let (i_left, i_right) = split_into_two_halfes(&i);

            if let Ok(shift) = C::bn_to_scalar(&BigNumber::from_slice(i_left)) {
                let parent_private_key: C::Scalar = self.private_key.unwrap_or(C::Scalar::zero());
                let parent_public_key = self.public_key;

                let child_private_key = parent_private_key.add(&shift);
                let child_public_key = parent_public_key + C::GENERATOR.mul(&shift);

                if child_public_key != C::IDENTITY {
                    return CKDOutput {
                        private_key: child_private_key,
                        chain_code: (*i_right).into(),
                    };
                }
            }

            i = hmac
                .clone()
                .chain_update([0x01])
                .chain_update(i_right)
                .chain_update(self.index.to_be_bytes())
                .finalize()
                .into_bytes()
        }
    }
}

/// Splits array `I` of 64 bytes into two arrays `I_L = I[..32]` and `I_R =
/// I[32..]`
fn split_into_two_halfes(
    i: &GenericArray<u8, U64>,
) -> (&GenericArray<u8, U32>, &GenericArray<u8, U32>) {
    generic_array::sequence::Split::split(i)
}

// Unit tests
// test vector taken from: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

/* Seed (hex): 000102030405060708090a0b0c0d0e0f

Chain m
chain code: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
private: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
public: 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2 */

#[test]
fn test_derive_master_key() {
    use crate::curve::TestCurve;

    let seed = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let mk_input = MasterKeyInput::new(&seed, CURVE_NAME.into()).unwrap();
    let master_key_output = MasterKeyInput::derive_master_key::<TestCurve>(&mk_input);
    assert_eq!(
        master_key_output.private_key.to_bytes(),
        [
            0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93,
            0xc9, 0xc5, 0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17,
            0xc8, 0x43, 0x6b, 0x35
        ]
        .into()
    );
    assert_eq!(
        master_key_output.chain_code,
        [
            0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e,
            0xac, 0x3a, 0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2, 0x27, 0xff,
            0xed, 0x37, 0xd5, 0x08
        ]
    );
}

/*
Chain m/0
chain code: f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c
private: abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e
public: 02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea
*/
#[test]
fn test_derive_child_key() {
    use crate::curve::TestCurve;

    // seed:
    // fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    let seed = [
        0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea, 0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5,
        0xd2, 0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba, 0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8,
        0xa5, 0xa2, 0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a, 0x87, 0x84, 0x81, 0x7e, 0x7b,
        0x78, 0x75, 0x72, 0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a, 0x57, 0x54, 0x51, 0x4e,
        0x4b, 0x48, 0x45, 0x42,
    ];
    let mk_input = MasterKeyInput::new(&seed, CURVE_NAME.into()).unwrap();
    let master_key_output = MasterKeyInput::derive_master_key::<TestCurve>(&mk_input);

    // derive the child key
    let pk = TestCurve::GENERATOR.mul(&master_key_output.private_key);
    let private_key = master_key_output.private_key;
    let public_key_bytes: Vec<u8> = pk.to_bytes().to_vec();

    // The expected values are:
    // chain code: 60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689
    // private: 4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e
    // public: 03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7

    // assert the chain code
    assert_eq!(
        master_key_output.chain_code,
        [
            0x60, 0x49, 0x9f, 0x80, 0x1b, 0x89, 0x6d, 0x83, 0x17, 0x9a, 0x43, 0x74, 0xae, 0xb7,
            0x82, 0x2a, 0xae, 0xac, 0xea, 0xa0, 0xdb, 0x1f, 0x85, 0xee, 0x3e, 0x90, 0x4c, 0x4d,
            0xef, 0xbd, 0x96, 0x89
        ]
    );
    // assert the private key
    assert_eq!(
        master_key_output.private_key.to_bytes(),
        [
            0x4b, 0x03, 0xd6, 0xfc, 0x34, 0x04, 0x55, 0xb3, 0x63, 0xf5, 0x10, 0x20, 0xad, 0x3e,
            0xcc, 0xa4, 0xf0, 0x85, 0x02, 0x80, 0xcf, 0x43, 0x6c, 0x70, 0xc7, 0x27, 0x92, 0x3f,
            0x6d, 0xb4, 0x6c, 0x3e
        ]
        .into()
    );
    // assert the public key (it only works for K256)
    assert_eq!(
        public_key_bytes,
        [
            0x03, 0xcb, 0xca, 0xa9, 0xc9, 0x8c, 0x87, 0x7a, 0x26, 0x97, 0x7d, 0x00, 0x82, 0x5c,
            0x95, 0x6a, 0x23, 0x8e, 0x8d, 0xdd, 0xfb, 0xd3, 0x22, 0xcc, 0xe4, 0xf7, 0x4b, 0x0b,
            0x5b, 0xd6, 0xac, 0xe4, 0xa7
        ]
    );
    let public_key = TestCurve::try_from_bytes(&public_key_bytes).unwrap();

    let ckd_input: CKDInput<TestCurve> = CKDInput::new(
        Some(private_key),
        public_key,
        master_key_output.chain_code,
        0,
    )
    .unwrap();
    let child_key_output = ckd_input.derive_public_shift();
    // assert the chain code (it only works for K256)
    assert_eq!(
        child_key_output.chain_code,
        [
            0xf0, 0x90, 0x9a, 0xff, 0xaa, 0x7e, 0xe7, 0xab, 0xe5, 0xdd, 0x4e, 0x10, 0x05, 0x98,
            0xd4, 0xdc, 0x53, 0xcd, 0x70, 0x9d, 0x5a, 0x5c, 0x2c, 0xac, 0x40, 0xe7, 0x41, 0x2f,
            0x23, 0x2f, 0x7c, 0x9c
        ]
    );
    // assert the private key (it only works for K256)
    let private_key: <TestCurve as CurveTrait>::Scalar = child_key_output.private_key;
    assert_eq!(
        private_key.to_bytes().as_slice(),
        [
            0xab, 0xe7, 0x4a, 0x98, 0xf6, 0xc7, 0xea, 0xbe, 0xe0, 0x42, 0x8f, 0x53, 0x79, 0x8f,
            0x0a, 0xb8, 0xaa, 0x1b, 0xd3, 0x78, 0x73, 0x99, 0x90, 0x41, 0x70, 0x3c, 0x74, 0x2f,
            0x15, 0xac, 0x7e, 0x1e
        ]
    );
}
