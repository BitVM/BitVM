use crate::treepp::*;
use bitcoin::{absolute, Amount, Sequence, Transaction, TxIn, TxOut, Witness};

use super::super::context::BridgeContext;
use super::super::graph::FEE_AMOUNT;

use super::bridge::*;
use super::helper::*;
pub struct PegOutTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
}

impl PegOutTransaction {
    pub fn new(context: &BridgeContext, input0: Input, input1: Input) -> Self {
        let operator_pubkey = context
            .operator_pubkey
            .expect("operator_pubkey is required in context");
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");
        let withdrawer_pubkey = context
            .withdrawer_pubkey
            .expect("withdrawer_pubkey is required in context");

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

        let total_input_amount = input0.1 + input1.1 - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(&withdrawer_pubkey)
                .script_pubkey(),
        };

        PegOutTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1],
                output: vec![_output0],
            },
            prev_outs: vec![],
        }
    }
}

impl BridgeTransaction for PegOutTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        todo!();
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        todo!()
    }
}
