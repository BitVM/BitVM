use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::{All, PublicKey as Secp256k1PublicKey},
    Network, PrivateKey, PublicKey, XOnlyPublicKey,
};
use musig2::{secp::Point, KeyAggContext};

pub trait BaseContext {
    fn network(&self) -> Network;
    fn secp(&self) -> &Secp256k1<All>;
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey>;
    fn n_of_n_public_key(&self) -> &PublicKey;
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey;
}

pub fn generate_keys_from_secret(
    network: Network,
    secret: &str,
) -> (Secp256k1<All>, Keypair, PublicKey) {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_str(&secp, secret).unwrap();
    let private_key = PrivateKey::new(keypair.secret_key(), network);
    let public_key = PublicKey::from_private_key(&secp, &private_key);

    (secp, keypair, public_key)
}

pub fn generate_n_of_n_public_key(n_of_n_public_keys: &[PublicKey]) -> (PublicKey, XOnlyPublicKey) {
    let public_keys: Vec<Point> = n_of_n_public_keys
        .iter()
        .map(|&public_key| public_key.inner.into())
        .collect();

    let key_agg_context = KeyAggContext::new(public_keys).unwrap();
    let aggregated_key: Secp256k1PublicKey = key_agg_context.aggregated_pubkey();

    let n_of_n_public_key = PublicKey::from(aggregated_key);
    let n_of_n_taproot_public_key = XOnlyPublicKey::from(n_of_n_public_key);

    (n_of_n_public_key, n_of_n_taproot_public_key)
}
