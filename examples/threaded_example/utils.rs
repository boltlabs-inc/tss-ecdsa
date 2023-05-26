use serde::{Deserialize, Serialize};
use tss_ecdsa::Message;

/// Sub-protocol of tss-ecdsa.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum SubProtocol {
    KeyGeneration,
    AuxInfo,
    Presign,
    Sign,
}

/// Outgoing message from worker threads to main thread.
#[derive(Debug, Serialize, Deserialize)]
pub enum MessageFromWorker {
    /// Worker made progress on sub-protocol, returning some messages.
    FinishedRound(Vec<Message>),
    /// Current sub-protocol ended.
    SubProtocolEnded,
}
