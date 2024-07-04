use crate::treepp::*;
use bitcoin::{
    absolute, consensus, key::Keypair, Amount, ScriptBuf, Sequence, TapSighashType, Transaction,
    TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{connector::*, connector_a::ConnectorA},
        contexts::{base::BaseContext, operator::OperatorContext},
        graphs::base::FEE_AMOUNT,
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
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
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
                input: vec![_input0],
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

    // allows for aggregating multiple inputs and one refund output
    pub fn add_inputs_and_output(
        &mut self,
        context: &dyn BaseContext,
        inputs: &Vec<InputWithScript>,
        keypair: &Keypair,
        output_script_pubkey: ScriptBuf,
    ) {
        if self.tx.input.len() > 1 {
            panic!("Cannot add any more inputs or outputs.");
        }

        // check total input amount
        let mut total_input_amount = Amount::from_sat(0);
        for input in inputs {
            total_input_amount += input.amount;
        }
        if total_input_amount < self.input_amount_crowdfunding {
            panic!("Total input amount too low. Add additional input.");
        } else if total_input_amount > self.input_amount_crowdfunding {
            // add refund output
            let _output = TxOut {
                value: total_input_amount - self.input_amount_crowdfunding,
                script_pubkey: output_script_pubkey,
            };
            self.tx.output.push(_output);
        }

        // add crowdfunding inputs
        let sighash_type = bitcoin::EcdsaSighashType::AllPlusAnyoneCanPay;
        let mut input_index = self.tx.input.len();
        for input in inputs {
            let _input = TxIn {
                previous_output: input.outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };
            self.tx.input.push(_input);

            // add witness
            populate_p2wsh_witness(
                context,
                &mut self.tx,
                input_index,
                sighash_type,
                input.script,
                input.amount,
                &vec![&keypair],
            );

            input_index += 1;
        }
    }
}

impl BaseTransaction for ChallengeTransaction {
    fn finalize(&self) -> Transaction {
        if self.tx.input.len() < 2 {
            panic!("Missing input. Call add_inputs_and_output before finalizing");
        }

        self.tx.clone()
    }
}
