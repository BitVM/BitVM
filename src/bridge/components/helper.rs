use crate::treepp::*;
use bitcoin::{Address, Amount, Network, OutPoint, PublicKey, XOnlyPublicKey};

pub const NUM_BLOCKS_PER_WEEK: u32 = 1008;

pub struct Input {
    pub outpoint: OutPoint,
    pub amount: Amount,
}

pub fn generate_burn_script() -> Script {
    script! {
        OP_RETURN // TODO replace with Satoshi's address (Unspendable pubkey)
    }
}

pub fn generate_burn_script_address() -> Address {
    Address::p2wsh(&generate_burn_script(), Network::Testnet)
}

pub fn generate_pay_to_pubkey_script(public_key: &PublicKey) -> Script {
    script! {
        { *public_key }
        OP_CHECKSIG
    }
}

pub fn generate_pay_to_pubkey_script_address(public_key: &PublicKey) -> Address {
    Address::p2wsh(&generate_pay_to_pubkey_script(public_key), Network::Testnet)
}

pub fn generate_pay_to_pubkey_taproot_script(public_key: &XOnlyPublicKey) -> Script {
    script! {
        { *public_key }
        OP_CHECKSIG
    }
}

pub fn generate_pay_to_pubkey_taproot_script_address(public_key: &XOnlyPublicKey) -> Address {
    Address::p2wsh(
        &generate_pay_to_pubkey_taproot_script(public_key),
        Network::Testnet,
    )
}

pub fn generate_timelock_script(public_key: &PublicKey, weeks: u32) -> Script {
    script! {
      { NUM_BLOCKS_PER_WEEK * weeks }
      OP_CSV
      OP_DROP
      { *public_key }
      OP_CHECKSIG
    }
}

pub fn generate_timelock_script_address(public_key: &PublicKey, weeks: u32) -> Address {
    Address::p2wsh(
        &generate_timelock_script(public_key, weeks),
        Network::Testnet,
    )
}

pub fn generate_timelock_taproot_script(public_key: &XOnlyPublicKey, weeks: u32) -> Script {
    script! {
      { NUM_BLOCKS_PER_WEEK * weeks }
      OP_CSV
      OP_DROP
      { *public_key }
      OP_CHECKSIG
    }
}

pub fn generate_timelock_taproot_script_address(
    public_key: &XOnlyPublicKey,
    weeks: u32,
) -> Address {
    Address::p2wsh(
        &generate_timelock_taproot_script(public_key, weeks),
        Network::Testnet,
    )
}
