use crate::auxinfo::info::AuxInfoPublic;
use crate::errors::Result;
use crate::keygen::keyshare::KeySharePublic;
use crate::messages::PresignMessageType;
use crate::messages::{Message, MessageType};
use crate::paillier::PaillierCiphertext;
use crate::presign::round_one::{Private as RoundOnePrivate, Public as RoundOnePublic};
use crate::utils::k256_order;
use crate::zkp::piaffg::{PiAffgInput, PiAffgProof};
use crate::zkp::pilog::{PiLogInput, PiLogProof};
use crate::zkp::Proof;
use crate::CurvePoint;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Private {
    pub(crate) beta: BigNumber,
    pub(crate) beta_hat: BigNumber,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Public {
    pub(crate) D: PaillierCiphertext,
    pub(crate) D_hat: PaillierCiphertext,
    pub(crate) F: PaillierCiphertext,
    pub(crate) F_hat: PaillierCiphertext,
    pub(crate) Gamma: CurvePoint,
    pub(crate) psi: PiAffgProof,
    pub(crate) psi_hat: PiAffgProof,
    pub(crate) psi_prime: PiLogProof,
}

impl Public {
    fn verify(
        &self,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_keyshare_public: &KeySharePublic,
        receiver_r1_private: &RoundOnePrivate,
        sender_r1_public: &RoundOnePublic,
    ) -> Result<()> {
        let g = CurvePoint::GENERATOR;

        // Verify the psi proof
        let psi_input = PiAffgInput::new(
            &receiver_auxinfo_public.params,
            &g,
            receiver_auxinfo_public.pk.n(),
            sender_auxinfo_public.pk.n(),
            &receiver_r1_private.K.0,
            &self.D.0,
            &self.F.0,
            &self.Gamma,
        );
        self.psi.verify(&psi_input)?;

        // Verify the psi_hat proof
        let psi_hat_input = PiAffgInput::new(
            &receiver_auxinfo_public.params,
            &g,
            receiver_auxinfo_public.pk.n(),
            sender_auxinfo_public.pk.n(),
            &receiver_r1_private.K.0,
            &self.D_hat.0,
            &self.F_hat.0,
            &sender_keyshare_public.X,
        );
        self.psi_hat.verify(&psi_hat_input)?;

        // Verify the psi_prime proof
        let psi_prime_input = PiLogInput::new(
            &receiver_auxinfo_public.params,
            &k256_order(),
            sender_auxinfo_public.pk.n(),
            &sender_r1_public.G.0,
            &self.Gamma,
            &g,
        );
        self.psi_prime.verify(&psi_prime_input)?;

        Ok(())
    }

    pub(crate) fn from_message(
        message: &Message,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_keyshare_public: &KeySharePublic,
        receiver_r1_private: &super::round_one::Private,
        sender_r1_public: &super::round_one::Public,
    ) -> Result<Self> {
        if message.message_type() != MessageType::Presign(PresignMessageType::RoundTwo) {
            return bail!("Wrong message type, expected MessageType::RoundTwo");
        }
        let round_two_public: Self = deserialize!(&message.unverified_bytes)?;

        match round_two_public.verify(
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_keyshare_public,
            receiver_r1_private,
            sender_r1_public,
        ) {
            Ok(()) => Ok(round_two_public),
            Err(e) => bail!("Failed to verify round two public: {}", e),
        }
    }
}
