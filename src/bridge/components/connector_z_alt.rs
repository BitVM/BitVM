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
pub fn connector_z_alt_spend_info(
  evm_address: String,
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey,
  depositor_pubkey: XOnlyPublicKey,
) -> TaprootSpendInfo {
  let secp = Secp256k1::new();

  // leaf[0] is TimeLock script that the depositor can spend after timelock, if leaf[1] has not been spent
  let leaf0 = script! {
    { NUM_BLOCKS_PER_WEEK * 2 }
    OP_CSV
    OP_DROP
    { depositor_pubkey }
    OP_CHECKSIGVERIFY
  };

  // leaf[1] is spendable by a multisig of depositor and OPK and VPK[1…N]
  // the transaction script contains an [evm_address] (inscription data)
  let leaf1 = script! {
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

  return TaprootBuilder::new()
      .add_leaf(0, leaf0)
      .add_leaf(1, leaf1)
      .expect("Unable to add pre_sign script as leaf")
      .finalize(&secp, n_of_n_pubkey) // TODO is this supposed to be pre-signed?
      .expect("Unable to finalize OP_CHECKSIG taproot");
}

pub fn connector_z_alt_address(
  evm_address: String,
  operator_pubkey: XOnlyPublicKey,
  n_of_n_pubkey: XOnlyPublicKey,
  depositor_pubkey: XOnlyPublicKey,
) -> Address {
  Address::p2tr_tweaked(
      connector_z_alt_spend_info(evm_address, operator_pubkey, n_of_n_pubkey, depositor_pubkey).output_key(),
      Network::Testnet,
  )
}
