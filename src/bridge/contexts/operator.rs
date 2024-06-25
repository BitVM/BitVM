use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Network, PublicKey, XOnlyPublicKey,
};

use super::base::{generate_keys_from_secret, BaseContext};

pub struct OperatorContext {
    pub network: Network,
    pub secp: Secp256k1<All>,

    pub operator_keypair: Keypair,
    pub operator_public_key: PublicKey,
    pub operator_taproot_public_key: XOnlyPublicKey,

    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,

    pub withdrawer_public_key: Option<PublicKey>,
    pub withdrawer_taproot_public_key: Option<XOnlyPublicKey>,

    pub evm_address: String,
}

impl BaseContext for OperatorContext {
    fn network(&self) -> Network { self.network }
    fn secp(&self) -> &Secp256k1<All> { &self.secp }
}

impl OperatorContext {
    pub fn new(
        network: Network,
        operator_secret: &str,
        n_of_n_public_key: &PublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        evm_address: &str,
    ) -> Self {
        let (secp, keypair, public_key, taproot_public_key) =
            generate_keys_from_secret(network, operator_secret);

        OperatorContext {
            network,
            secp,

            operator_keypair: keypair,
            operator_public_key: public_key,
            operator_taproot_public_key: taproot_public_key,

            n_of_n_public_key: n_of_n_public_key.clone(),
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),

            withdrawer_public_key: None,
            withdrawer_taproot_public_key: None,

            evm_address: evm_address.to_string(),
        }
    }

    pub fn initialize_withdrawer(
        &mut self,
        withdrawer_public_key: &PublicKey,
        withdrawer_taproot_public_key: &XOnlyPublicKey,
    ) {
        self.withdrawer_public_key = Some(withdrawer_public_key.clone());
        self.withdrawer_taproot_public_key = Some(withdrawer_taproot_public_key.clone());
    }
}
