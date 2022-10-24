use crate::auxinfo::info::AuxInfoPublic;
use crate::errors::Result;
use crate::messages::PresignMessageType;
use crate::messages::{Message, MessageType};
use crate::paillier::PaillierCiphertext;
use crate::zkp::Proof;
use crate::zkp::{pienc::PiEncProof, setup::ZkSetupParameters};
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Private {
    pub(crate) k: BigNumber,
    pub(crate) rho: BigNumber,
    pub(crate) gamma: BigNumber,
    pub(crate) nu: BigNumber,
    pub(crate) G: PaillierCiphertext, // Technically can be public but is only one per party
    pub(crate) K: PaillierCiphertext, // Technically can be public but is only one per party
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Public {
    pub(crate) K: PaillierCiphertext,
    pub(crate) G: PaillierCiphertext,
    pub(crate) proof: PiEncProof,
}

impl Public {
    /// Verify M(vrfy, Π^enc_i, (ssid, j), (I_ε, K_j), ψ_{i,j}) = 1
    /// setup_params should be the receiving party's setup parameters
    /// the modulus N should be the sending party's modulus N
    fn verify(
        &self,
        receiver_setup_params: &ZkSetupParameters,
        sender_modulus: &BigNumber,
    ) -> Result<()> {
        let input =
            crate::zkp::pienc::PiEncInput::new(receiver_setup_params, sender_modulus, &self.K);

        self.proof.verify(&input)
    }

    pub(crate) fn from_message(
        message: &Message,
        receiver_keygen_public: &AuxInfoPublic,
        sender_keygen_public: &AuxInfoPublic,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Presign(PresignMessageType::RoundOne) {
            return bail!("Wrong message type, expected MessageType::RoundOne");
        }
        let round_one_public: Self = deserialize!(&message.unverified_bytes)?;

        match round_one_public.verify(&receiver_keygen_public.params, sender_keygen_public.pk.n()) {
            Ok(()) => Ok(round_one_public),
            Err(e) => bail!("Failed to verify round one public: {}", e),
        }
    }
}
