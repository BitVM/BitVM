use crate::treepp::*;
use bitcoin::{Address, CompressedPublicKey, Network, PublicKey, ScriptBuf, XOnlyPublicKey};
use lazy_static::lazy_static;
use std::str::FromStr;

lazy_static! {
    // TODO replace these public keys
    pub static ref UNSPENDABLE_PUBLIC_KEY: PublicKey = PublicKey::from_str(
        "0405f818748aecbc8c67a4e61a03cee506888f49480cf343363b04908ed51e25b9615f244c38311983fb0f5b99e3fd52f255c5cc47a03ee2d85e78eaf6fa76bb9d"
    )
    .unwrap();
    pub static ref UNSPENDABLE_TAPROOT_PUBLIC_KEY: XOnlyPublicKey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    )
    .unwrap();
}

//TODO: replace with real value, and delete this comment
// pub const NUM_BLOCKS_PER_WEEK: u32 = 1008;
pub const NUM_BLOCKS_PER_WEEK: u32 = 1;

pub fn generate_burn_script() -> ScriptBuf {
    generate_pay_to_pubkey_script(&UNSPENDABLE_PUBLIC_KEY)
}

pub fn generate_burn_script_address(network: Network) -> Address {
    Address::p2wsh(&generate_burn_script(), network)
}

pub fn generate_burn_taproot_script() -> ScriptBuf {
    generate_pay_to_pubkey_taproot_script(&UNSPENDABLE_TAPROOT_PUBLIC_KEY)
}

pub fn generate_pay_to_pubkey_script(public_key: &PublicKey) -> ScriptBuf {
    script! {
        { *public_key }
        OP_CHECKSIG
    }
    .compile()
}

pub fn generate_p2wpkh_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2wpkh(
        &CompressedPublicKey::try_from(*public_key).expect("Could not compress public key"),
        network,
    )
}

pub fn generate_pay_to_pubkey_script_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2wsh(&generate_pay_to_pubkey_script(public_key), network)
}

pub fn generate_pay_to_pubkey_taproot_script(public_key: &XOnlyPublicKey) -> ScriptBuf {
    script! {
        { *public_key }
        OP_CHECKSIG
    }
    .compile()
}

pub fn generate_pay_to_pubkey_taproot_script_address(
    network: Network,
    public_key: &XOnlyPublicKey,
) -> Address {
    Address::p2wsh(&generate_pay_to_pubkey_taproot_script(public_key), network)
}

pub fn generate_timelock_script(public_key: &PublicKey, num_blocks_timelock: u32) -> ScriptBuf {
    script! {
      { num_blocks_timelock }
      OP_CSV
      OP_DROP
      { *public_key }
      OP_CHECKSIG
    }
    .compile()
}

pub fn generate_timelock_script_address(
    network: Network,
    public_key: &PublicKey,
    num_blocks_timelock: u32,
) -> Address {
    Address::p2wsh(
        &generate_timelock_script(public_key, num_blocks_timelock),
        network,
    )
}

pub fn generate_timelock_taproot_script(
    public_key: &XOnlyPublicKey,
    num_blocks_timelock: u32,
) -> ScriptBuf {
    script! {
      { num_blocks_timelock }
      OP_CSV
      OP_DROP
      { *public_key }
      OP_CHECKSIG
    }
    .compile()
}

pub fn generate_timelock_taproot_script_address(
    network: Network,
    public_key: &XOnlyPublicKey,
    num_blocks_timelock: u32,
) -> Address {
    Address::p2wsh(
        &generate_timelock_taproot_script(public_key, num_blocks_timelock),
        network,
    )
}
