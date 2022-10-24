pub(crate) mod piaffg;
pub(crate) mod pienc;
pub(crate) mod pifac;
pub(crate) mod pilog;
pub(crate) mod pimod;
pub(crate) mod piprm;
pub(crate) mod pisch;
pub(crate) mod setup;

use crate::errors::Result;
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
pub(crate) trait Proof: Sized + Serialize + DeserializeOwned {
    type CommonInput;
    type ProverSecret;

    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self>;

    fn verify(&self, input: &Self::CommonInput) -> Result<()>;
}
