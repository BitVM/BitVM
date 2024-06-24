use crate::treepp::*;
use serde::{Deserialize, Serialize};
use bitcoin::{absolute, Amount, Sequence, Transaction, TxIn, TxOut, Witness, consensus};

use super::{
    super::{context::BridgeContext, graph::FEE_AMOUNT, scripts::*},
    bridge::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PegOutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
}

impl PegOutTransaction {
    pub fn new(context: &BridgeContext, input0: Input, input1: Input) -> Self {
        let withdrawer_public_key = context
            .withdrawer_public_key
            .expect("withdrawer_public_key is required in context");

        // QUESTION Why do we need this input from Bob?
        let _input0 = TxIn {
            previous_output: input0.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _input1 = TxIn {
            previous_output: input1.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_output_amount = input0.amount + input1.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(
                context.network,
                &withdrawer_public_key,
            )
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

    fn finalize(&self, context: &BridgeContext) -> Transaction { todo!() }
}
