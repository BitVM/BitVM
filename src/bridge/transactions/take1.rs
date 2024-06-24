use crate::treepp::*;
use bitcoin::{
    absolute, key::Keypair, sighash::Prevouts, Amount, TapSighashType, Transaction, TxOut,
};

use super::{
    super::{
        connectors::{
            connector::*, connector_0::Connector0, connector_1::Connector1,
            connector_a::ConnectorA, connector_b::ConnectorB,
        },
        context::BridgeContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    bridge::*,
    signing::*,
};

pub struct Take1Transaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_a: ConnectorA,
    connector_b: ConnectorB,
}

impl Take1Transaction {
    pub fn new(
        context: &BridgeContext,
        input0: Input,
        input1: Input,
        input2: Input,
        input3: Input,
    ) -> Self {
        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let operator_taproot_public_key = context
            .operator_taproot_public_key
            .expect("operator_taproot_public_key is required in context");

        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_0 = Connector0::new(context.network, &n_of_n_public_key);
        let connector_1 = Connector1::new(context.network, &operator_public_key);
        let connector_a = ConnectorA::new(
            context.network,
            &operator_taproot_public_key,
            &n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(context.network, &n_of_n_taproot_public_key);

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
                &operator_public_key,
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

    fn pre_sign_input0(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 0;
        let sighash_type = bitcoin::EcdsaSighashType::All;
        let script = &self.prev_scripts[input_index];
        let value = self.prev_outs[input_index].value;

        populate_p2wsh_witness(
            context,
            &mut self.tx,
            input_index,
            sighash_type,
            script,
            value,
            &vec![n_of_n_keypair],
        );
    }

    fn pre_sign_input1(&mut self, context: &BridgeContext, operator_keypair: &Keypair) {
        let input_index = 1;
        let sighash_type = bitcoin::EcdsaSighashType::All;
        let script = &self.prev_scripts[input_index];
        let value = self.prev_outs[input_index].value;

        populate_p2wsh_witness(
            context,
            &mut self.tx,
            input_index,
            sighash_type,
            script,
            value,
            &vec![operator_keypair],
        );
    }

    fn pre_sign_input2(&mut self, context: &BridgeContext, operator_keypair: &Keypair) {
        let input_index = 2;
        let prevouts = Prevouts::All(&self.prev_outs);
        let sighash_type = TapSighashType::All;
        let script = &self.prev_scripts[input_index];
        let taproot_spend_info = self.connector_a.generate_taproot_spend_info();

        populate_taproot_input_witness(
            context,
            &mut self.tx,
            &prevouts,
            input_index,
            sighash_type,
            &taproot_spend_info,
            script,
            &vec![&operator_keypair],
        );
    }

    fn pre_sign_input3(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 3;
        let prevouts = Prevouts::All(&self.prev_outs);
        let sighash_type = TapSighashType::All;
        let script = &self.prev_scripts[input_index];
        let taproot_spend_info = self.connector_b.generate_taproot_spend_info();

        populate_taproot_input_witness(
            context,
            &mut self.tx,
            &prevouts,
            input_index,
            sighash_type,
            &taproot_spend_info,
            script,
            &vec![&n_of_n_keypair],
        );
    }
}

impl BridgeTransaction for Take1Transaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        let operator_keypair = context
            .operator_keypair
            .expect("operator_keypair required in context");

        self.pre_sign_input0(context, &n_of_n_keypair);
        self.pre_sign_input1(context, &n_of_n_keypair);
        self.pre_sign_input2(context, &operator_keypair);
        self.pre_sign_input3(context, &n_of_n_keypair);
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction { self.tx.clone() }
}
