use crate::treepp::*;
use bitcoin::{
    key::Secp256k1, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_a_spend_info(
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey
) -> TaprootSpendInfo {

  // leaf[0]: spendable by operator
  let leaf0 = script! {
    { operator_pubkey }
    OP_CHECKSIG
  };

  // leaf[1]: spendable by operator with sighash flag=“Single|AnyoneCanPay”, spendable along with any other inputs such that the output value exceeds V*1%
  let leaf1 = script! {
    { operator_pubkey }
    OP_CHECKSIG
  };

  let secp = Secp256k1::new();

  return TaprootBuilder::new()
    .add_leaf(0, leaf0)
    .expect("Unable to add leaf0")
    .add_leaf(1, leaf1)
    .expect("Unable to add leaf1")
    .finalize(&secp, n_of_n_pubkey)
    .expect("Unable to finalize taproot");
}

pub fn connector_a_address(
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey
) -> Address {
  Address::p2tr_tweaked(
      connector_a_spend_info(operator_pubkey, n_of_n_pubkey).output_key(),
      Network::Testnet,
  )
}
