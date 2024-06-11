use crate::treepp::*;
use bitcoin::{
    absolute, key::Keypair, secp256k1::Message, sighash::{Prevouts, SighashCache}, taproot::LeafVersion, Address, Amount, Network, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness
  };

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT, N_OF_N_SECRET};

use super::bridge::*;
use super::connector_z::*;
use super::helper::*;

pub struct PegInDepositTransaction {
  tx: Transaction,
  prev_outs: Vec<TxOut>,
  prev_scripts: Vec<Script>,
  evm_address: String,
}

impl PegInDepositTransaction {
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

    PegInDepositTransaction {
          tx: Transaction {
              version: bitcoin::transaction::Version(2),
              lock_time: absolute::LockTime::ZERO,
              input: vec![_input0],
              output: vec![_output0],
          },
          prev_outs: vec![], // TODO
          prev_scripts: vec![], // TODO
          evm_address: evm_address,
      }
  }
}

impl BridgeTransaction for PegInDepositTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        todo!()
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        let mut tx = self.tx.clone();
        tx
    }
}
