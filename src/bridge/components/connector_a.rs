// TODO
// leaf[0] -> 2 week checksequenceverify to refund tokens to depositor
// leaf[1] -> input to peg in with inscribed ethereum address for destination of wrapped bitcoin


use crate::treepp::*;
use bitcoin::{
    key::Secp256k1, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};


// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_a_spend_info(
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey
) -> (TaprootSpendInfo, TaprootSpendInfo) {
  let secp = Secp256k1::new();

  // leaf[0]: spendable by operator
  let take1_script = script! {
    { operator_pubkey }
    OP_CHECKSIGVERIFY
  };
  let leaf0 = TaprootBuilder::new()
    .add_leaf(0, take1_script)
    .expect("Unable to add pre_sign script as leaf")
    .finalize(&secp, operator_pubkey) // Doesn't need to be presigned
    .expect("Unable to finalize OP_CHECKSIG taproot");

  // leaf[1]: spendable by operator? (I think this is incorrect) with sighash flag=“Single|AnyoneCanPay”, spendable along with any other inputs such that the output value exceeds V*1%
  let challenge_script = script! {
    { operator_pubkey }
    OP_CHECKSIGVERIFY
  };
  let leaf1 = TaprootBuilder::new()
    .add_leaf(0, challenge_script)
    .expect("Unable to add pre_sign script as leaf")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize OP_CHECKSIG taproot");

  (leaf0, leaf1)
}

pub fn connector_a_address(
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey
) -> Address {
  Address::p2tr_tweaked(
      connector_a_spend_info(n_of_n_pubkey, operator_pubkey).1.output_key(),
      Network::Testnet,
  )
}

pub fn connector_a_pre_sign_address(
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey
) -> Address {
  Address::p2tr_tweaked(
      connector_a_spend_info(n_of_n_pubkey, operator_pubkey).0.output_key(),
      Network::Testnet,
  )
}