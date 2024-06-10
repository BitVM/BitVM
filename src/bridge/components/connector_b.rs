use crate::treepp::*;
use bitcoin::{
    key::Secp256k1, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

use super::helper::*;

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_b_spend_info(
  n_of_n_pubkey: XOnlyPublicKey
) -> TaprootSpendInfo {

  // Leaf[0]: spendable by multisig of OPK and VPK[1…N]
  let leaf0 = script! {
    { n_of_n_pubkey }
    OP_CHECKSIG
  };

  // Leaf[1]: spendable by multisig of OPK and VPK[1…N] plus providing witness to the lock script of Assert
  let leaf1 = script! {
    // TODO commit to intermediate values
    { n_of_n_pubkey }
    OP_CHECKSIG
  };

  // Leaf[2]: spendable by Burn after a TimeLock of 4 weeks plus multisig of OPK and VPK[1…N]
  let leaf2 = script! {
    { NUM_BLOCKS_PER_WEEK * 4 }
    OP_CSV
    OP_DROP
    { n_of_n_pubkey }
    OP_CHECKSIG
  };

  let secp = Secp256k1::new();

  return TaprootBuilder::new()
    .add_leaf(0, leaf0)
    .expect("Unable to add leaf0")
    .add_leaf(1, leaf1)
    .expect("Unable to add leaf1")
    .add_leaf(2, leaf2)
    .expect("Unable to add leaf2")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize taproot");
}

pub fn connector_b_address(n_of_n_pubkey: XOnlyPublicKey) -> Address {
  Address::p2tr_tweaked(
      connector_b_spend_info(n_of_n_pubkey).output_key(),
      Network::Testnet,
  )
}
