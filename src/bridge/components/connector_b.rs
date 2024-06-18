use crate::treepp::*;
use bitcoin::{
    key::Secp256k1, opcodes::all::*, script::Builder, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

use super::helper::*;

// Leaf[0]: spendable by multisig of OPK and VPK[1…N]
pub fn generate_leaf0(n_of_n_pubkey: &XOnlyPublicKey) -> Script {
    generate_pay_to_pubkey_script(n_of_n_pubkey)
}

// Leaf[1]: spendable by multisig of OPK and VPK[1…N] plus providing witness to the lock script of Assert
pub fn generate_leaf1(n_of_n_pubkey: &XOnlyPublicKey) -> Script {
    script! {
      // TODO commit to intermediate values
      { *n_of_n_pubkey }
      OP_CHECKSIG
    }
}

// Leaf[2]: spendable by Burn after a TimeLock of 4 weeks plus multisig of OPK and VPK[1…N]
pub fn generate_leaf2(n_of_n_pubkey: &XOnlyPublicKey, num_blocks_timelock: u32) -> Script {
    script! {
      { num_blocks_timelock }
      OP_CSV
      OP_DROP
      { *n_of_n_pubkey }
      OP_CHECKSIG
    }
}

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn generate_spend_info(n_of_n_pubkey: &XOnlyPublicKey, num_blocks_timelock: u32) -> TaprootSpendInfo {
    TaprootBuilder::new()
        .add_leaf(2, generate_leaf0(n_of_n_pubkey))
        .expect("Unable to add leaf0")
        .add_leaf(2, generate_leaf1(n_of_n_pubkey))
        .expect("Unable to add leaf1")
        .add_leaf(1, generate_leaf2(n_of_n_pubkey, num_blocks_timelock))
        .expect("Unable to add leaf2")
        .finalize(&Secp256k1::new(), n_of_n_pubkey.clone())
        .expect("Unable to finalize taproot")
}

pub fn generate_address(n_of_n_pubkey: &XOnlyPublicKey, num_blocks_timelock: u32) -> Address {
    Address::p2tr_tweaked(
        generate_spend_info(n_of_n_pubkey, num_blocks_timelock).output_key(),
        Network::Testnet,
    )
}
