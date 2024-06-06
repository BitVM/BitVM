// TODO
// leaf[0] -> 2 week checksequenceverify to refund tokens to depositor
// leaf[1] -> input to peg in with inscribed ethereum address for destination of wrapped bitcoin

use std::string;

use crate::treepp::*;
use bitcoin::{
    hashes::{ripemd160, Hash}, key::Secp256k1, opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP}, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

use super::helper::*;

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_a_alt_spend_info(
  operator_pubkey: XOnlyPublicKey,
) -> TaprootSpendInfo {
  let secp = Secp256k1::new();

  // leaf[0]: spendable by operator
  let leaf0 = script! {
    { operator_pubkey }
    OP_CHECKSIGVERIFY
  };

  // leaf[1]: spendable by operator? (I think this is incorrect) with sighash flag=“Single|AnyoneCanPay”, spendable along with any other inputs such that the output value exceeds V*1%
  let leaf1 = script! {
    { operator_pubkey }
    OP_CHECKSIGVERIFY
  };

  return TaprootBuilder::new()
    .add_leaf(0, leaf0)
    .expect("Unable to add pre_sign script as leaf")
    .add_leaf(1, leaf1)
    .expect("Unable to add pre_sign script as leaf")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize OP_CHECKSIG taproot");
}

pub fn connector_a_alt_address(
  operator_pubkey: XOnlyPublicKey
) -> Address {
  Address::p2tr_tweaked(
      connector_a_alt_spend_info(operator_pubkey).output_key(),
      Network::Testnet,
  )
}
