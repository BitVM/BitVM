use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Network, PublicKey, XOnlyPublicKey,
};

use super::base::{generate_keys_from_secret, BaseContext};

pub struct WithdrawerContext {
    pub network: Network,
    pub secp: Secp256k1<All>,

    pub withdrawer_keypair: Keypair,
    pub withdrawer_public_key: PublicKey,
    pub withdrawer_taproot_public_key: XOnlyPublicKey,

    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,

    pub evm_address: String,
}

impl BaseContext for WithdrawerContext {
    fn network(&self) -> Network { self.network }
    fn secp(&self) -> &Secp256k1<All> { &self.secp }
}

impl WithdrawerContext {
    pub fn new(
        network: Network,
        withdrawer_secret: &str,
        n_of_n_public_key: &PublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        evm_address: &str,
    ) -> Self {
        let (secp, keypair, public_key, taproot_public_key) =
            generate_keys_from_secret(network, withdrawer_secret);

        WithdrawerContext {
            network,
            secp,

            withdrawer_keypair: keypair,
            withdrawer_public_key: public_key,
            withdrawer_taproot_public_key: taproot_public_key,

            n_of_n_public_key: n_of_n_public_key.clone(),
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),

            evm_address: evm_address.to_string(),
        }
    }
}
