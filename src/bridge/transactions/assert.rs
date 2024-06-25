use crate::treepp::*;
use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            connector::*, connector_2::Connector2, connector_3::Connector3,
            connector_b::ConnectorB, connector_c::ConnectorC,
        },
        context::BridgeContext,
        graph::{DUST_AMOUNT, FEE_AMOUNT},
    },
    bridge::*,
    signing::*,
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

impl TransactionBase for AssertTransaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_2 = Connector2::new(context.network, &operator_public_key);
        let connector_3 = Connector3::new(context.network, &n_of_n_public_key);
        let connector_b = ConnectorB::new(context.network, &n_of_n_taproot_public_key);
        let connector_c = ConnectorC::new(context.network, &n_of_n_taproot_public_key);

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
}

impl BridgeTransaction for AssertTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        pre_sign_taproot_input(
            self,
            context,
            0,
            TapSighashType::All,
            self.connector_b.generate_taproot_spend_info(),
            &vec![&n_of_n_keypair],
        );
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction { self.tx.clone() }
}
