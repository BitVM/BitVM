use crate::treepp::*;
use bitcoin::{absolute, Amount, EcdsaSighashType, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            connector::*, connector_0::Connector0, connector_1::Connector1,
            connector_a::ConnectorA, connector_b::ConnectorB,
        },
        contexts::operator::OperatorContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct Take1Transaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_a: ConnectorA,
    connector_b: ConnectorB,
}

impl PreSignedTransaction for Take1Transaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
}

impl Take1Transaction {
    pub fn new(
        context: &OperatorContext,
        input0: Input,
        input1: Input,
        input2: Input,
        input3: Input,
    ) -> Self {
        let connector_0 = Connector0::new(context.network, &context.n_of_n_public_key);
        let connector_1 = Connector1::new(context.network, &context.operator_public_key);
        let connector_a = ConnectorA::new(
            context.network,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(context.network, &context.n_of_n_taproot_public_key);

        let _input0 = connector_0.generate_tx_in(&input0);

        let _input1 = connector_1.generate_tx_in(&input1);

        let _input2 = connector_a.generate_taproot_leaf_tx_in(0, &input2);

        let _input3 = connector_b.generate_taproot_leaf_tx_in(0, &input3);

        let total_output_amount = input0.amount + input1.amount + input2.amount + input3.amount
            - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(
                context.network,
                &context.operator_public_key,
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
                    value: input0.amount,
                    script_pubkey: connector_0.generate_address().script_pubkey(),
                },
                TxOut {
                    value: input1.amount,
                    script_pubkey: connector_1.generate_address().script_pubkey(),
                },
                TxOut {
                    value: input2.amount,
                    script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input3.amount,
                    script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_script(),
                connector_1.generate_script(),
                connector_a.generate_taproot_leaf_script(0),
                connector_b.generate_taproot_leaf_script(0),
            ],
            connector_a,
            connector_b,
        }
    }
}

impl BaseTransaction for Take1Transaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

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

        pre_sign_taproot_input(
            self,
            context,
            2,
            TapSighashType::All,
            self.connector_a.generate_taproot_spend_info(),
            &vec![&operator_keypair],
        );

        pre_sign_taproot_input(
            self,
            context,
            3,
            TapSighashType::All,
            self.connector_b.generate_taproot_spend_info(),
            &vec![&n_of_n_keypair],
        );
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction { self.tx.clone() }
}
