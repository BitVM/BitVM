use crate::treepp::*;
use bitcoin::{
    absolute,
    Address, Amount, Network, OutPoint, Sequence,
    Transaction, TxIn, TxOut, Witness,
    ScriptBuf, XOnlyPublicKey,
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT, N_OF_N_SECRET};

use super::bridge::*;
use super::connector_z::*;
use super::helper::*;

pub struct PegInRefundTransaction {
  tx: Transaction,
  prev_outs: Vec<TxOut>,
}

impl PegInRefundTransaction {
  pub fn new(context: &BridgeContext, input0: Input) -> Self {
      let operator_pubkey = context
          .operator_pubkey
          .expect("operator_pubkey is required in context");
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
        script_pubkey: Address::p2wsh(
            &generate_pay_to_pubkey_script(depositor_pubkey),
            Network::Testnet
        )
        .script_pubkey(),
    };

    PegInRefundTransaction {
          tx: Transaction {
              version: bitcoin::transaction::Version(2),
              lock_time: absolute::LockTime::ZERO,
              input: vec![_input0],
              output: vec![_output0],
          },
          prev_outs: vec![
            TxOut {
                value: input0.1,
                script_pubkey: connector_z_address(evm_address, n_of_n_pubkey, depositor_pubkey).script_pubkey(),
            },
        ],
      }
  }
}

impl BridgeTransaction for PegInRefundTransaction {
  fn pre_sign(&mut self, context: &BridgeContext) {
      todo!();
  }

  fn finalize(&self, context: &BridgeContext) -> Transaction { todo!() }
}