use crate::treepp::*;
use bitcoin::{
    key::Secp256k1, taproot::{TaprootBuilder, TaprootSpendInfo}, Address, Network, XOnlyPublicKey
};

use super::helper::*;

// leaf[0] is TimeLock script that the depositor can spend after timelock, if leaf[1] has not been spent
pub fn generate_leaf0(
  depositor_pubkey: &XOnlyPublicKey,
) -> Script {
  script! {
    { NUM_BLOCKS_PER_WEEK * 2 }
    OP_CSV
    OP_DROP
    { depositor_pubkey.clone() }
    OP_CHECKSIG
  }
}

// leaf[1] is spendable by a multisig of depositor and OPK and VPK[1…N]
  // the transaction script contains an [evm_address] (inscription data)
pub fn generate_leaf1(
  evm_address: &String,
  n_of_n_pubkey: &XOnlyPublicKey,
  depositor_pubkey: &XOnlyPublicKey,
) -> Script {
  script! {
    OP_FALSE
    OP_IF
    { String::from("ord").into_bytes() } // TODO Decide if this metadata is needed or not
    1
    { String::from("text/plain;charset=utf-8").into_bytes() } // TODO change to json for clearer meaning
    0
    { evm_address.clone().into_bytes() }
    OP_ENDIF
    { n_of_n_pubkey.clone() }
    OP_CHECKSIGVERIFY
    { depositor_pubkey.clone() }
    OP_CHECKSIG
  }
}

pub fn generate_spend_info(
  evm_address: &String,
  n_of_n_pubkey: &XOnlyPublicKey,
  depositor_pubkey: &XOnlyPublicKey,
) -> TaprootSpendInfo {
  TaprootBuilder::new()
      .add_leaf(0, generate_leaf0(depositor_pubkey))
      .expect("Unable to add leaf0")
      .add_leaf(1, generate_leaf1(evm_address, n_of_n_pubkey, depositor_pubkey))
      .expect("Unable to add leaf1")
      .finalize(&Secp256k1::new(), depositor_pubkey.clone()) // TODO: should this be depositor or n-of-n
      .expect("Unable to finalize ttaproot")
}

pub fn generate_address(
  evm_address: &String,
  n_of_n_pubkey: &XOnlyPublicKey,
  depositor_pubkey: &XOnlyPublicKey
) -> Address {
  Address::p2tr_tweaked(
    generate_spend_info(evm_address, n_of_n_pubkey, depositor_pubkey).output_key(),
      Network::Testnet,
  )
}
