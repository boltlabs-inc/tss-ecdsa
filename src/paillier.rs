use crate::utils::random_bn_in_z_star;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierCiphertext(pub(crate) BigNumber);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierEncryptionKey(pub(crate) libpaillier::EncryptionKey);

impl PaillierEncryptionKey {
    pub(crate) fn n(&self) -> &BigNumber {
        self.0.n()
    }

    pub(crate) fn encrypt(&self, x: &BigNumber) -> (BigNumber, BigNumber) {
        let mut rng = rand::rngs::OsRng;
        let nonce = random_bn_in_z_star(&mut rng, self.0.n());

        let one = BigNumber::one();
        let base = one + self.n();
        let a = base.modpow(x, self.0.nn());
        let b = nonce.modpow(self.n(), self.0.nn());
        let c = a.modmul(&b, self.0.nn());
        (c, nonce)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierDecryptionKey(pub(crate) libpaillier::DecryptionKey);

impl PaillierDecryptionKey {
    pub(crate) fn decrypt(&self, c: &BigNumber) -> Option<Vec<u8>> {
        self.0.decrypt(c)
    }
}
