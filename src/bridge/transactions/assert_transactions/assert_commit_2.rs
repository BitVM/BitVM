use bitcoin::{absolute, consensus, Amount, EcdsaSighashType, ScriptBuf, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use crate::bridge::contexts::operator::OperatorContext;

use super::super::{
    super::{
        connectors::{base::*, connector_e_2::ConnectorE2},
        graphs::base::FEE_AMOUNT,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommit2Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for AssertCommit2Transaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl AssertCommit2Transaction {
    pub fn new(context: &OperatorContext, connector_e_2: &ConnectorE2, input_0: Input) -> Self {
        let mut this = Self::new_for_validation(connector_e_2, input_0);

        this.sign_input_0(context);

        this
    }

    pub fn new_for_validation(connector_e_2: &ConnectorE2, input_0: Input) -> Self {
        let _input_0 = connector_e_2.generate_tx_in(&input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_e_2.generate_address().script_pubkey(),
        };

        AssertCommit2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_e_2.generate_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_e_2.generate_script()],
        }
    }

    fn sign_input_0(&mut self, context: &OperatorContext) {
        let input_index = 0;
        pre_sign_p2wsh_input(
            self,
            context,
            input_index,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for AssertCommit2Transaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
