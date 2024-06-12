use crate::treepp::*;
use bitcoin::{
  absolute, key::Keypair, secp256k1::Message, sighash::{Prevouts, SighashCache}, taproot::LeafVersion, Amount, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT, DEPOSITOR_SECRET};

use super::bridge::*;
use super::connector_z::*;
use super::helper::*;

pub struct PegInConfirmTransaction {
  tx: Transaction,
  prev_outs: Vec<TxOut>,
  prev_scripts: Vec<Script>,
  evm_address: String,
}

impl PegInConfirmTransaction {
  pub fn new(context: &BridgeContext, input0: Input, evm_address: String) -> Self {
      let n_of_n_pubkey = context
          .n_of_n_pubkey
          .expect("n_of_n_pubkey is required in context");
    let depositor_pubkey = context
        .depositor_pubkey
        .expect("depositor_pubkey is required in context");

      let _input0 = TxIn {
          previous_output: input0.0,
          script_sig: Script::new(),
          sequence: Sequence::MAX,
          witness: Witness::default(),
      };

      let _output0 = TxOut {
        value: input0.1 - Amount::from_sat(FEE_AMOUNT),
        script_pubkey: generate_address(&evm_address, &n_of_n_pubkey, &depositor_pubkey).script_pubkey(),
    };

    PegInConfirmTransaction {
          tx: Transaction {
              version: bitcoin::transaction::Version(2),
              lock_time: absolute::LockTime::ZERO,
              input: vec![_input0],
              output: vec![_output0],
          },
          prev_outs: vec![
            TxOut {
                value: input0.1,
                script_pubkey: generate_address(&evm_address, &n_of_n_pubkey, &depositor_pubkey).script_pubkey(),
            },
        ],
        prev_scripts: vec![
          generate_leaf1(&evm_address, &n_of_n_pubkey, &depositor_pubkey)
        ],
        evm_address: evm_address,
      }
  }
}

impl BridgeTransaction for PegInConfirmTransaction {
  fn pre_sign(&mut self, context: &BridgeContext) {
    let input_index = 0;
    let leaf_index = 1;

    let evm_address = &self.evm_address;

    let n_of_n_pubkey = context
        .n_of_n_pubkey
        .expect("n_of_n_pubkey required in context");

        let depositor_key = Keypair::from_seckey_str(&context.secp, DEPOSITOR_SECRET).unwrap();
        let depositor_pubkey = context
          .depositor_pubkey
          .expect("depositor_pubkey is required in context");

    let prevouts = Prevouts::All(&self.prev_outs);
    let prevout_leaf = (
        self.prev_scripts[input_index].clone(),
        LeafVersion::TapScript,
    );

    let sighash_type = TapSighashType::All;
    let leaf_hash = TapLeafHash::from_script(&prevout_leaf.0, prevout_leaf.1);

    let sighash = SighashCache::new(&self.tx)
        .taproot_script_spend_signature_hash(leaf_index, &prevouts, leaf_hash, sighash_type)
        .expect("Failed to construct sighash");

    let signature = context.secp.sign_schnorr_no_aux_rand(&Message::from(sighash), &depositor_key); // TODO: Does n-of-n have to presign this?
    self.tx.input[input_index].witness.push(bitcoin::taproot::Signature {
      signature,
      sighash_type,
  }.to_vec());

    let spend_info = generate_spend_info(&evm_address, &n_of_n_pubkey, &depositor_pubkey);
    let control_block = spend_info
        .control_block(&prevout_leaf)
        .expect("Unable to create Control block");
    self.tx.input[input_index].witness.push(prevout_leaf.0.to_bytes());
    self.tx.input[input_index].witness.push(control_block.serialize());
  }

  fn finalize(&self, context: &BridgeContext) -> Transaction {
    self.tx.clone()
  }
}
