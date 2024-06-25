use crate::treepp::*;
use bitcoin::{
    absolute, consensus, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{contexts::operator::OperatorContext, graph::FEE_AMOUNT, scripts::*},
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PegOutTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl PreSignedTransaction for PegOutTransaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
}

impl PegOutTransaction {
    pub fn new(context: &OperatorContext, input0: Input, input1: Input) -> Self {
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
            prev_scripts: vec![],
        }
    }
}

impl BaseTransaction for PegOutTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        todo!();
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { todo!() }
}
