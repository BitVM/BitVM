use crate::treepp::*;
use bitcoin::{
    absolute,
    Address, Amount, Network, Sequence,
    Transaction, TxIn, TxOut, Witness,
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT};

use super::bridge::*;
use super::connector_a::*;
use super::connector_b::*;
use super::helper::*;

pub struct Take1Transaction {
  tx: Transaction,
  prev_outs: Vec<TxOut>,
}

impl Take1Transaction {
  pub fn new(context: &BridgeContext, input0: Input, input1: Input, input2: Input, input3: Input) -> Self {
      let operator_pubkey = context
          .operator_pubkey
          .expect("operator_pubkey is required in context");
      let n_of_n_pubkey = context
          .n_of_n_pubkey
          .expect("n_of_n_pubkey is required in context");

      let _input0 = TxIn {
          previous_output: input0.0,
          script_sig: Script::new(),
          sequence: Sequence::MAX,
          witness: Witness::default(),
      };

      let _input1 = TxIn {
        previous_output: input1.0,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
      };

      let _input2 = TxIn {
        previous_output: input2.0,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
      };

      let _input3 = TxIn {
        previous_output: input3.0,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
      };

      let _output0 = TxOut {
          value: input0.1 + input3.1 - Amount::from_sat(FEE_AMOUNT),
          script_pubkey: Address::p2wsh(
              &generate_pay_to_pubkey_script(operator_pubkey),
              Network::Testnet
          )
          .script_pubkey(),
      };

  Take1Transaction {
          tx: Transaction {
              version: bitcoin::transaction::Version(2),
              lock_time: absolute::LockTime::ZERO,
              input: vec![_input0, _input1, _input2, _input3],
              output: vec![_output0],
          },
          prev_outs: vec![
            TxOut {
                value: input0.1,
                script_pubkey: Address::p2wsh(&generate_pre_sign_script(n_of_n_pubkey), Network::Testnet).script_pubkey(),
            },
            TxOut {
                value: input1.1,
                script_pubkey: Address::p2wsh(&generate_timelock_script(n_of_n_pubkey, 2), Network::Testnet).script_pubkey(),
            },
            TxOut {
              value: input2.1,
              script_pubkey: connector_a_address(operator_pubkey, n_of_n_pubkey).script_pubkey(),
            },
            TxOut {
                value: input3.1,
                script_pubkey: connector_b_address(n_of_n_pubkey).script_pubkey(),
            },
        ],
      }
  }
}

impl BridgeTransaction for Take1Transaction {
  fn pre_sign(&mut self, context: &BridgeContext) {
      todo!();
  }

  fn finalize(&self, context: &BridgeContext) -> Transaction { todo!() }
}