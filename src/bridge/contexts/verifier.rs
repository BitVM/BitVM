use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Network, PublicKey, XOnlyPublicKey,
};

use super::base::{generate_keys_from_secret, generate_n_of_n_public_key, BaseContext};

pub struct VerifierContext {
    pub network: Network,
    pub secp: Secp256k1<All>,

    pub verifier_keypair: Keypair,
    pub verifier_public_key: PublicKey,

    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for VerifierContext {
    fn network(&self) -> Network { self.network }
    fn secp(&self) -> &Secp256k1<All> { &self.secp }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> { &self.n_of_n_public_keys }
    fn n_of_n_public_key(&self) -> &PublicKey { &self.n_of_n_public_key }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey { &self.n_of_n_taproot_public_key }
}

impl VerifierContext {
    pub fn new(
        network: Network,
        verifier_secret: &str,
        n_of_n_public_keys: &Vec<PublicKey>,
    ) -> Self {
        let (secp, keypair, public_key) = generate_keys_from_secret(network, verifier_secret);
        let (n_of_n_public_key, n_of_n_taproot_public_key) =
            generate_n_of_n_public_key(n_of_n_public_keys);

        VerifierContext {
            network,
            secp,

            verifier_keypair: keypair,
            verifier_public_key: public_key,

            n_of_n_public_keys: n_of_n_public_keys.clone(),
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}
