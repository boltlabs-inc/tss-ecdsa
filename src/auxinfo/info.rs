use crate::errors::Result;
use crate::paillier::{PaillierDecryptionKey, PaillierEncryptionKey};
use crate::zkp::setup::ZkSetupParameters;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct AuxInfoPrivate {
    pub(crate) sk: PaillierDecryptionKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoPublic {
    pub(crate) pk: PaillierEncryptionKey,
    pub(crate) params: ZkSetupParameters,
}

impl AuxInfoPublic {
    /// Verifies that the public key's modulus matches the ZKSetupParameters modulus
    /// N, and that the parameters have appropriate s and t values.
    pub(crate) fn verify(&self) -> Result<()> {
        if self.pk.n() != &self.params.N {
            return verify_err!("Mismatch with pk.n() and params.N");
        }
        self.params.verify()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoWitnesses {
    pub(crate) p: BigNumber,
    pub(crate) q: BigNumber,
}
