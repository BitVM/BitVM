use bitcoin::{absolute, Amount, EcdsaSighashType, ScriptBuf, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            connector::*, connector_0::Connector0, connector_2::Connector2, connector_3::Connector3,
        },
        contexts::{operator::OperatorContext, verifier::VerifierContext},
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct Take2Transaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for Take2Transaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl Take2Transaction {
    pub fn new(context: &OperatorContext, input0: Input, input1: Input, input2: Input) -> Self {
        let connector_0 = Connector0::new(context.network, &context.n_of_n_public_key);
        let connector_2 = Connector2::new(context.network, &context.operator_public_key);
        let connector_3 = Connector3::new(context.network, &context.n_of_n_public_key);

        let _input0 = connector_0.generate_tx_in(&input0);

        let _input1 = connector_2.generate_tx_in(&input1);

        let _input2 = connector_3.generate_tx_in(&input2);

        let total_output_amount =
            input0.amount + input1.amount + input2.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(
                context.network,
                &context.operator_public_key,
            )
            .script_pubkey(),
        };

        let mut this = Take2Transaction {
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
        };

        this.sign_input1(context);

        this
    }

    fn sign_input0(&mut self, context: &VerifierContext) {
        pre_sign_p2wsh_input(
            self,
            context,
            0,
            EcdsaSighashType::All,
            &vec![&context.n_of_n_keypair],
        );
    }

    fn sign_input1(&mut self, context: &OperatorContext) {
        pre_sign_p2wsh_input(
            self,
            context,
            1,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }

    fn sign_input2(&mut self, context: &VerifierContext) {
        pre_sign_p2wsh_input(
            self,
            context,
            2,
            EcdsaSighashType::All,
            &vec![&context.n_of_n_keypair],
        );
    }

    pub fn pre_sign(&mut self, context: &VerifierContext) {
        self.sign_input0(context);
        self.sign_input2(context);
    }
}

impl BaseTransaction for Take2Transaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
