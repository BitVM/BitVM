use crate::treepp::*;
use bitcoin::{
    absolute, consensus, key::Keypair, Amount, OutPoint, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{connector::*, connector_a::ConnectorA},
        contexts::{base::BaseContext, operator::OperatorContext},
        graph::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
    signing::populate_p2wsh_witness,
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

impl PreSignedTransaction for ChallengeTransaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
}

impl ChallengeTransaction {
    pub fn new(
        context: &OperatorContext,
        input0: Input,
        input_amount_crowdfunding: Amount,
    ) -> Self {
        let connector_a = ConnectorA::new(
            context.network,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
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
                &context.operator_public_key,
            )
            .script_pubkey(),
        };

        let mut this = ChallengeTransaction {
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
        };

        this.sign_input0(context);

        this
    }

    fn sign_input0(&mut self, context: &OperatorContext) {
        pre_sign_taproot_input(
            self,
            context,
            0,
            TapSighashType::SinglePlusAnyoneCanPay,
            self.connector_a.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    // TODO allow for aggregating multiple inputs and refund outputs
    pub fn add_input(
        &mut self,
        context: &BaseContext,
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

impl BaseTransaction for ChallengeTransaction {
    fn finalize(&self) -> Transaction {
        if self.tx.input.len() < 2 {
            panic!("Missing input. Call add_input before finalizing");
        }

        self.tx.clone()
    }
}
