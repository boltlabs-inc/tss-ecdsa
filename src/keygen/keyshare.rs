use crate::utils::CurvePoint;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeySharePrivate {
    pub(crate) x: BigNumber, // in the range [1, q)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeySharePublic {
    pub(crate) X: CurvePoint,
}
