use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Network, PublicKey, XOnlyPublicKey,
};

use super::base::{generate_keys_from_secret, generate_n_of_n_public_key, BaseContext};

pub struct DepositorContext {
    pub network: Network,
    pub secp: Secp256k1<All>,

    pub depositor_keypair: Keypair,
    pub depositor_public_key: PublicKey,
    pub depositor_taproot_public_key: XOnlyPublicKey,

    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for DepositorContext {
    fn network(&self) -> Network { self.network }
    fn secp(&self) -> &Secp256k1<All> { &self.secp }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> { &self.n_of_n_public_keys }
    fn n_of_n_public_key(&self) -> &PublicKey { &self.n_of_n_public_key }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey { &self.n_of_n_taproot_public_key }
}

impl DepositorContext {
    pub fn new(
        network: Network,
        depositor_secret: &str,
        n_of_n_public_keys: &Vec<PublicKey>,
    ) -> Self {
        let (secp, keypair, public_key) = generate_keys_from_secret(network, depositor_secret);
        let (n_of_n_public_key, n_of_n_taproot_public_key) =
            generate_n_of_n_public_key(n_of_n_public_keys);

        DepositorContext {
            network,
            secp,

            depositor_keypair: keypair,
            depositor_public_key: public_key,
            depositor_taproot_public_key: XOnlyPublicKey::from(public_key),

            n_of_n_public_keys: n_of_n_public_keys.clone(),
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}
