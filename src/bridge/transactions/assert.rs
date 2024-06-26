use crate::{bridge::contexts::verifier::VerifierContext, treepp::*};
use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            connector::*, connector_2::Connector2, connector_3::Connector3,
            connector_b::ConnectorB, connector_c::ConnectorC,
        },
        contexts::operator::OperatorContext,
        graph::{DUST_AMOUNT, FEE_AMOUNT},
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct AssertTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_b: ConnectorB,
}

impl PreSignedTransaction for AssertTransaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl AssertTransaction {
    pub fn new(context: &OperatorContext, input0: Input) -> Self {
        let connector_2 = Connector2::new(context.network, &context.operator_public_key);
        let connector_3 = Connector3::new(context.network, &context.n_of_n_public_key);
        let connector_b = ConnectorB::new(context.network, &context.n_of_n_taproot_public_key);
        let connector_c = ConnectorC::new(context.network, &context.n_of_n_taproot_public_key);

        let _input0 = connector_b.generate_taproot_leaf_tx_in(1, &input0);

        let total_output_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_2.generate_address().script_pubkey(),
        };

        let _output1 = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_3.generate_address().script_pubkey(),
        };

        let _output2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
        };

        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf_script(1)],
            connector_b,
        }
    }

    fn sign_input0(&mut self, context: &VerifierContext) {
        pre_sign_taproot_input(
            self,
            context,
            0,
            TapSighashType::All,
            self.connector_b.generate_taproot_spend_info(),
            &vec![&context.n_of_n_keypair],
        );
    }

    fn pre_sign(&mut self, context: &VerifierContext) { self.sign_input0(context); }
}

impl BaseTransaction for AssertTransaction {
    fn finalize(&mut self) -> Transaction { self.tx.clone() }
}
