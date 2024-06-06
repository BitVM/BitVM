use crate::treepp::*;
use bitcoin::{
    hashes::{ripemd160, Hash}, key::Secp256k1, opcodes::{all::{OP_CHECKSIGADD, OP_CHECKSIGVERIFY}, OP_TRUE}, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

use super::helper::*;

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_b_alt_spend_info(
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey,
) -> TaprootSpendInfo {
  let secp = Secp256k1::new();

  // Leaf[0]: spendable by multisig of OPK and VPK[1…N]
  let leaf0 = script! {
    { operator_pubkey }
    OP_CHECKSIGVERIFY
    { n_of_n_pubkey }
    OP_CHECKSIGVERIFY
  };

  // Leaf[1]: spendable by multisig of OPK and VPK[1…N] plus providing witness to the lock script of Assert
  let leaf1 = script! {
    // TODO commit to intermediate values
    { operator_pubkey }
    OP_CHECKSIGVERIFY
    { n_of_n_pubkey }
    OP_CHECKSIGVERIFY
    OP_TRUE
  };


  // Leaf[2]: spendable by Burn after a TimeLock of 4 weeks plus multisig of OPK and VPK[1…N]
  let leaf2 = script! {
    { NUM_BLOCKS_PER_WEEK * 4 }
    OP_CSV
    OP_DROP
    { operator_pubkey }
    OP_CHECKSIGVERIFY
    { n_of_n_pubkey }
    OP_CHECKSIGVERIFY
    OP_TRUE
  };

  return TaprootBuilder::new()
    .add_leaf(0, leaf0)
    .add_leaf(1, leaf1)
    .add_leaf(2, leaf2)
    .expect("Unable to add pre_sign script as leaf")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize OP_CHECKSIG taproot");
}

pub fn connector_b_alt_address(operator_pubkey: XOnlyPublicKey, n_of_n_pubkey: XOnlyPublicKey) -> Address {
  Address::p2tr_tweaked(
      connector_b_alt_spend_info(operator_pubkey, n_of_n_pubkey).output_key(),
      Network::Testnet,
  )
}
