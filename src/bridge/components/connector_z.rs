// TODO
// leaf[0] -> 2 week checksequenceverify to refund tokens to depositor
// leaf[1] -> input to peg in with inscribed ethereum address for destination of wrapped bitcoin


use crate::treepp::*;
use bitcoin::{
    key::Secp256k1, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

use super::helper::*;

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_z_spend_info(
  evm_address: String,
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey,
  depositor_pubkey: XOnlyPublicKey,
) -> (TaprootSpendInfo, TaprootSpendInfo) {
  let secp = Secp256k1::new();

  // leaf[0] is TimeLock script that the depositor can spend after timelock, if leaf[1] has not been spent
  let timeout_script = script! {
    { NUM_BLOCKS_PER_WEEK * 2 }
    OP_CSV
    OP_DROP
    { depositor_pubkey }
    OP_CHECKSIGVERIFY
  };
  let leaf0 = TaprootBuilder::new()
    .add_leaf(0, timeout_script)
    .expect("Unable to add pre_sign script as leaf")
    .finalize(&secp, depositor_pubkey)
    .expect("Unable to finalize OP_CHECKSIG taproot");

  // leaf[1] is spendable by a multisig of depositor and OPK and VPK[1…N]
  // the transaction script contains an [evm_address] (inscription data)
  let peg_in_script = script! {
    OP_FALSE
    OP_IF
    { String::from("ord").into_bytes() }
    1
    { String::from("text/plain;charset=utf-8").into_bytes() } // TODO change to json for clearer meaning
    0
    { evm_address.into_bytes() }
    OP_ENDIF
    { operator_pubkey }
    OP_CHECKSIGVERIFY
    { n_of_n_pubkey }
    OP_CHECKSIGVERIFY
    { depositor_pubkey }
    OP_CHECKSIGVERIFY
  };
  let leaf1 = TaprootBuilder::new()
      .add_leaf(0, peg_in_script)
      .expect("Unable to add pre_sign script as leaf")
      .finalize(&secp, n_of_n_pubkey) // TODO is this supposed to be pre-signed?
      .expect("Unable to finalize OP_CHECKSIG taproot");


  (leaf0, leaf1)
}

pub fn connector_z_address(
  evm_address: String,
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey,
  depositor_pubkey: XOnlyPublicKey,
) -> Address {
  Address::p2tr_tweaked(
      connector_z_spend_info(evm_address, operator_pubkey, n_of_n_pubkey, depositor_pubkey).1.output_key(),
      Network::Testnet,
  )
}

pub fn connector_z_pre_sign_address(
  evm_address: String,
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey,
  depositor_pubkey: XOnlyPublicKey,
) -> Address {
  Address::p2tr_tweaked(
      connector_z_spend_info(evm_address, operator_pubkey, n_of_n_pubkey, depositor_pubkey).0.output_key(),
      Network::Testnet,
  )
}