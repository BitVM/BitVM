use crate::treepp::*;
use bitcoin::{
    absolute, consensus, key::Keypair, Amount, OutPoint, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct ChallengeTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    input_amount_crowdfunding: Amount,
    connector_a: ConnectorA,
}

impl TransactionBase for ChallengeTransaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
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

        pre_sign_taproot_input(
            self,
            context,
            0,
            TapSighashType::SinglePlusAnyoneCanPay,
            self.connector_a.generate_taproot_spend_info(),
            &vec![&operator_keypair],
        );
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        if (self.tx.input.len() < 2) {
            panic!("Missing input. Call add_input before finalizing");
        }

        self.tx.clone()
    }
}
