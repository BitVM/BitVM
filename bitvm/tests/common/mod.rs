use bitcoin::{key::{Keypair, Secp256k1}, secp256k1::PublicKey};

pub fn vicky_pubkey() -> PublicKey {
    let secp = Secp256k1::new();
    Keypair::from_seckey_str(
        &secp,
        "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497",
    )
    .unwrap()
    .public_key()
}
