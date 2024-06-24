use crate::treepp::*;
use bitcoin::{
    absolute, key::Keypair, sighash::Prevouts, Amount, OutPoint, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
};

use super::{
    super::{
        connectors::{connector::*, connector_a::ConnectorA},
        context::BridgeContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    bridge::*,
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

        let total_output_amount =
            input0.amount + input_amount_crowdfunding - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
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
            prev_outs: vec![
                TxOut {
                    value: input0.amount,
                    script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                },
                // input1 will be added later
            ],
            prev_scripts: vec![
                connector_a.generate_taproot_leaf_script(1),
                // input1's script will be added later
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

    // TODO allow for aggregating multiple inputs and refund outputs
    pub fn add_input(
        &mut self,
        context: &BridgeContext,
        input: OutPoint,
        script: &Script,
        keypair: &Keypair,
    ) {
        let input_index = 1;

        self.tx.input[input_index].previous_output = input;

        let sighash_type = bitcoin::EcdsaSighashType::AllPlusAnyoneCanPay;
        let value = self.input_amount_crowdfunding;

        populate_p2wsh_witness(
            context,
            &mut self.tx,
            input_index,
            sighash_type,
            script,
            value,
            &vec![&keypair],
        );
    }
}

impl BridgeTransaction for ChallengeTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let operator_keypair = context
            .operator_keypair
            .expect("operator_keypair is required in context");

        self.pre_sign_input0(context, &operator_keypair);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        if (self.tx.input.len() < 2) {
            panic!("Missing input. Call add_input before finalizing");
        }

        self.tx.clone()
    }
}
