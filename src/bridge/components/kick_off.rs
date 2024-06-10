use crate::treepp::*;
use bitcoin::{
    absolute,
    Address, Amount, Network, Sequence,
    Transaction, TxIn, TxOut, Witness,
    ScriptBuf, XOnlyPublicKey,
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT};

use super::bridge::*;
use super::connector_a::*;
use super::connector_b::*;
use super::helper::*;

pub struct KickOffTransaction {
  tx: Transaction,
  prev_outs: Vec<TxOut>,
}

impl KickOffTransaction {
  pub fn new(context: &BridgeContext, input0: Input) -> Self {
      let operator_pubkey = context
          .operator_pubkey
          .expect("operator_pubkey is required in context");
      let n_of_n_pubkey = context
          .n_of_n_pubkey
          .expect("n_of_n_pubkey is required in context");

          // TODO: Include commit y
      let _input0 = TxIn {
          previous_output: input0.0,
          script_sig: Script::new(),
          sequence: Sequence::MAX,
          witness: Witness::default(),
      };

      let _output0 = TxOut {
          value: Amount::from_sat(0),
          script_pubkey: Address::p2wsh(
              &generate_timelock_script(n_of_n_pubkey, 2),
              Network::Testnet
          )
          .script_pubkey(),
      };

      let _output1 = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Address::p2tr_tweaked(
            connector_a_spend_info(operator_pubkey, n_of_n_pubkey).output_key(),
            Network::Testnet,
        )
        .script_pubkey(),
    };

    let _output2 = TxOut {
      value: input0.1 - Amount::from_sat(FEE_AMOUNT),
      script_pubkey: Address::p2tr_tweaked(
          connector_b_spend_info(n_of_n_pubkey).output_key(),
          Network::Testnet,
      )
      .script_pubkey(),
  };

      KickOffTransaction {
          tx: Transaction {
              version: bitcoin::transaction::Version(2),
              lock_time: absolute::LockTime::ZERO,
              input: vec![_input0],
              output: vec![_output0, _output1, _output2],
          },
          prev_outs: vec![],
      }
  }
}

impl BridgeTransaction for KickOffTransaction {
  fn pre_sign(&mut self, context: &BridgeContext) {
      todo!();
  }

  fn finalize(&self, context: &BridgeContext) -> Transaction { todo!() }
}

// Currently only connector B.
pub fn generate_kickoff_leaves(
  n_of_n_pubkey: XOnlyPublicKey,
  operator_pubkey: XOnlyPublicKey,
) -> Vec<ScriptBuf> {
  // TODO: Single script with n_of_n_pubkey (Does something break if we don't sign with
  // operator_key?). Spendable by revealing all commitments
  todo!()
}
