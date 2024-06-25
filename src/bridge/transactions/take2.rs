use crate::treepp::*;
use bitcoin::{absolute, Amount, EcdsaSighashType, ScriptBuf, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            connector::*, connector_0::Connector0, connector_2::Connector2, connector_3::Connector3,
        },
        context::BridgeContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    bridge::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct Take2Transaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl TransactionBase for Take2Transaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
}

impl Take2Transaction {
    pub fn new(context: &BridgeContext, input0: Input, input1: Input, input2: Input) -> Self {
        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let connector_0 = Connector0::new(context.network, &n_of_n_public_key);
        let connector_2 = Connector2::new(context.network, &operator_public_key);
        let connector_3 = Connector3::new(context.network, &n_of_n_public_key);

        let _input0 = connector_0.generate_tx_in(&input0);

        let _input1 = connector_2.generate_tx_in(&input1);

        let _input2 = connector_3.generate_tx_in(&input2);

        let total_output_amount =
            input0.amount + input1.amount + input2.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(
                context.network,
                &operator_public_key,
            )
            .script_pubkey(),
        };

        Take2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1, _input2],
                output: vec![_output0],
            },
            prev_outs: vec![
                TxOut {
                    value: input0.amount,
                    script_pubkey: connector_0.generate_address().script_pubkey(),
                },
                TxOut {
                    value: input1.amount,
                    script_pubkey: connector_2.generate_address().script_pubkey(),
                },
                TxOut {
                    value: input2.amount,
                    script_pubkey: connector_3.generate_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_script(),
                connector_2.generate_script(),
                connector_3.generate_script(),
            ],
        }
    }
}

impl BridgeTransaction for Take2Transaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair is required in context");

        let operator_keypair = context
            .operator_keypair
            .expect("operator_keypair required in context");

        pre_sign_p2wsh_input(
            self,
            context,
            0,
            EcdsaSighashType::All,
            &vec![&n_of_n_keypair],
        );

        pre_sign_p2wsh_input(
            self,
            context,
            1,
            EcdsaSighashType::All,
            &vec![&operator_keypair],
        );

        pre_sign_p2wsh_input(
            self,
            context,
            2,
            EcdsaSighashType::All,
            &vec![&n_of_n_keypair],
        );
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { self.tx.clone() }
}
