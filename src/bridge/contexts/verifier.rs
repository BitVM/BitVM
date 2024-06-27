use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Network, PublicKey, XOnlyPublicKey,
};

use super::base::{generate_keys_from_secret, BaseContext};

pub struct VerifierContext {
    pub network: Network,
    pub secp: Secp256k1<All>,

    pub n_of_n_keypair: Keypair,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,

    pub operator_public_key: PublicKey,
    pub operator_taproot_public_key: XOnlyPublicKey,

    pub depositor_public_key: PublicKey,
    pub depositor_taproot_public_key: XOnlyPublicKey,

    pub withdrawer_public_key: PublicKey,
    pub withdrawer_taproot_public_key: XOnlyPublicKey,

    pub evm_address: String,
}

impl BaseContext for VerifierContext {
    fn network(&self) -> Network { self.network }
    fn secp(&self) -> &Secp256k1<All> { &self.secp }
}

impl VerifierContext {
    pub fn new(
        network: Network,
        n_of_n_secret: &str,
        operator_public_key: &PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        withdrawer_public_key: &PublicKey,
        withdrawer_taproot_public_key: &XOnlyPublicKey,
        evm_address: &str,
    ) -> Self {
        let (secp, keypair, public_key, taproot_public_key) =
            generate_keys_from_secret(network, n_of_n_secret);

        VerifierContext {
            network,
            secp,

            n_of_n_keypair: keypair,
            n_of_n_public_key: public_key,
            n_of_n_taproot_public_key: taproot_public_key,

            operator_public_key: operator_public_key.clone(),
            operator_taproot_public_key: operator_taproot_public_key.clone(),

            depositor_public_key: depositor_public_key.clone(),
            depositor_taproot_public_key: depositor_taproot_public_key.clone(),

            withdrawer_public_key: withdrawer_public_key.clone(),
            withdrawer_taproot_public_key: withdrawer_taproot_public_key.clone(),

            evm_address: evm_address.to_string(),
        }
    }
}
