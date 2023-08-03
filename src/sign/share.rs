use k256::Scalar;

/// A single participant's share of the signature.
#[allow(unused)]
#[derive(Debug)]
pub struct SignatureShare {
    share: Scalar,
}
