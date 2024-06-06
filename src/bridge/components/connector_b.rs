use crate::treepp::*;
use bitcoin::{
    key::Secp256k1, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

use super::helper::*;

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_b_spend_info(
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey,
) -> (TaprootSpendInfo, TaprootSpendInfo, TaprootSpendInfo) {
  let secp = Secp256k1::new();

  // Leaf[0]: spendable by multisig of OPK and VPK[1…N]
  let take1_script = script! {
    { operator_pubkey }
    OP_CHECKSIGVERIFY
    { n_of_n_pubkey }
    OP_CHECKSIGVERIFY
  };
  let leaf0 = TaprootBuilder::new()
    .add_leaf(0, take1_script)
    .expect("Unable to add pre_sign script as leaf")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize OP_CHECKSIG taproot");

  // Leaf[1]: spendable by multisig of OPK and VPK[1…N] plus providing witness to the lock script of Assert
  let assert_script = script! {
    // TODO commit to intermediate values
    { operator_pubkey }
    OP_CHECKSIGVERIFY
    { n_of_n_pubkey }
    OP_CHECKSIGVERIFY
    OP_TRUE
  };
  let leaf1 = TaprootBuilder::new()
    .add_leaf(0, assert_script)
    .expect("Unable to add pre_sign script as leaf")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize OP_CHECKSIG taproot");


  // Leaf[2]: spendable by Burn after a TimeLock of 4 weeks plus multisig of OPK and VPK[1…N]
  let timeout_script = script! {
    { NUM_BLOCKS_PER_WEEK * 4 }
    OP_CSV
    OP_DROP
    { operator_pubkey }
    OP_CHECKSIGVERIFY
    { n_of_n_pubkey }
    OP_CHECKSIGVERIFY
    OP_TRUE
  };
  let leaf2 = TaprootBuilder::new()
    .add_leaf(0, timeout_script)
    .expect("Unable to add pre_sign script as leaf")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize OP_CHECKSIG taproot");

  (leaf0, leaf1, leaf2)
}

pub fn connector_b_address(operator_pubkey: XOnlyPublicKey, n_of_n_pubkey: XOnlyPublicKey) -> Address {
  Address::p2tr_tweaked(
      connector_b_spend_info(operator_pubkey, n_of_n_pubkey).1.output_key(),
      Network::Testnet,
  )
}

pub fn connector_b_pre_sign_address(operator_pubkey: XOnlyPublicKey, n_of_n_pubkey: XOnlyPublicKey) -> Address {
  Address::p2tr_tweaked(
      connector_b_spend_info(operator_pubkey, n_of_n_pubkey).0.output_key(),
      Network::Testnet,
  )
}