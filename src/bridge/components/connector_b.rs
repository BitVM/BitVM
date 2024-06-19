use crate::treepp::*;
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, XOnlyPublicKey,
};

use super::helper::*;

// Leaf[0]: spendable by multisig of OPK and VPK[1…N]
pub fn generate_taproot_leaf0(n_of_n_public_key: &XOnlyPublicKey) -> Script {
    generate_pay_to_pubkey_taproot_script(n_of_n_public_key)
}

// Leaf[1]: spendable by multisig of OPK and VPK[1…N] plus providing witness to the lock script of Assert
pub fn generate_taproot_leaf1(n_of_n_public_key: &XOnlyPublicKey) -> Script {
    script! {
      // TODO commit to intermediate values
      { *n_of_n_public_key }
      OP_CHECKSIG
    }
}

// Leaf[2]: spendable by Burn after a TimeLock of 4 weeks plus multisig of OPK and VPK[1…N]
pub fn generate_taproot_leaf2(n_of_n_public_key: &XOnlyPublicKey) -> Script {
    script! {
      { NUM_BLOCKS_PER_WEEK * 4 }
      OP_CSV
      OP_DROP
      { *n_of_n_public_key }
      OP_CHECKSIG
    }
}

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn generate_taproot_spend_info(n_of_n_public_key: &XOnlyPublicKey) -> TaprootSpendInfo {
    TaprootBuilder::new()
        .add_leaf(1, generate_taproot_leaf0(n_of_n_public_key))
        .expect("Unable to add leaf0")
        .add_leaf(2, generate_taproot_leaf1(n_of_n_public_key))
        .expect("Unable to add leaf1")
        .add_leaf(2, generate_taproot_leaf2(n_of_n_public_key))
        .expect("Unable to add leaf2")
        .finalize(&Secp256k1::new(), n_of_n_public_key.clone())
        .expect("Unable to finalize taproot")
}

pub fn generate_taproot_address(n_of_n_public_key: &XOnlyPublicKey) -> Address {
    Address::p2tr_tweaked(
        generate_taproot_spend_info(n_of_n_public_key).output_key(),
        Network::Testnet,
    )
}
