use crate::treepp::*;
use bitcoin::{
    absolute, key::Keypair, sighash::Prevouts, Amount, OutPoint, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
};

use super::{
    super::{context::BridgeContext, graph::FEE_AMOUNT},
    bridge::*,
    connector::*,
    connector_a::ConnectorA,
    helper::*,
    signing::*,
};

pub struct ChallengeTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    input_amount_crowdfunding: Amount,
    connector_a: ConnectorA,
}

impl ChallengeTransaction {
    pub fn new(context: &BridgeContext, input0: Input, input_amount_crowdfunding: Amount) -> Self {
        let depositor_public_key = context
            .depositor_public_key
            .expect("operator_public_key is required in context");

        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let operator_taproot_public_key = context
            .operator_taproot_public_key
            .expect("operator_taproot_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_a = ConnectorA::new(
            context.network,
            &operator_taproot_public_key,
            &n_of_n_taproot_public_key,
        );

        let _input0 = connector_a.generate_taproot_leaf_tx_in(1, &input0);

        let _input1 = TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount =
            input0.amount + input_amount_crowdfunding - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(
                context.network,
                &operator_public_key,
            )
            .script_pubkey(),
        };

        ChallengeTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                // TODO add input1
            }],
            prev_scripts: vec![
                connector_a.generate_taproot_leaf_script(1), // TODO add input1
                generate_pay_to_pubkey_script(&depositor_public_key), // This script may not be known until it's actually mined, so it should go in finalize
            ],
            input_amount_crowdfunding,
            connector_a,
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, operator_keypair: &Keypair) {
        let input_index = 0;
        let prevouts = Prevouts::One(input_index, &self.prev_outs[input_index]);
        let sighash_type = TapSighashType::SinglePlusAnyoneCanPay; // TODO: shouldn't be Sighash All + AnyoneCanPay?
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

    fn pre_sign_input1(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 1;
        let sighash_type = bitcoin::EcdsaSighashType::AllPlusAnyoneCanPay;
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

    pub fn add_input(&mut self, context: &BridgeContext, input: OutPoint) {
        // TODO: keypair should be refactored and either pre_sign_input1 or add_input should exist but not both
        let depositor_keypair = context
            .depositor_keypair
            .expect("depositor_keypair required in context");

        let input_index = 1;

        self.tx.input[input_index].previous_output = input;

        let sighash_type = bitcoin::EcdsaSighashType::AllPlusAnyoneCanPay;
        let script = &self.prev_scripts[input_index];
        let value = self.input_amount_crowdfunding;

        populate_p2wsh_witness(
            context,
            &mut self.tx,
            input_index,
            sighash_type,
            script,
            value,
            &vec![&depositor_keypair],
        );
    }
}

impl BridgeTransaction for ChallengeTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let operator_keypair = context
            .operator_keypair
            .expect("operator_keypair is required in context");

        self.pre_sign_input0(context, &operator_keypair);

        // QUESTION How do we pre-sign input1?
        // self.pre_sign_input1(
        //     context,
        //     &operator_keypair,
        //     &operator_taproot_public_key,
        //     &n_of_n_keypair,
        //     &n_of_n_taproot_public_key,
        // );
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { self.tx.clone() }
}
