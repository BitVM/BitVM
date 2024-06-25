use crate::treepp::*;
use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{connector::*, connector_b::ConnectorB},
        context::BridgeContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    bridge::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct BurnTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_b: ConnectorB,
    reward_output_amount: Amount,
}

impl TransactionBase for BurnTransaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
}

impl BurnTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_b = ConnectorB::new(context.network, &n_of_n_taproot_public_key);

        let _input0 = connector_b.generate_taproot_leaf_tx_in(2, &input0);

        let total_output_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        // Output[0]: value=V*2%*95% to burn
        let _output0 = TxOut {
            value: total_output_amount * 95 / 100,
            script_pubkey: generate_burn_script_address(context.network).script_pubkey(),
        };

        BurnTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf_script(2)],
            connector_b,
            reward_output_amount: total_output_amount - (total_output_amount * 95 / 100),
        }
    }

    pub fn add_output(&mut self, output_script_pubkey: ScriptBuf) {
        let output_index = 1;

        // Add output
        self.tx.output[output_index] = TxOut {
            value: self.reward_output_amount,
            script_pubkey: output_script_pubkey,
        };

        // TODO: Doesn't this needs to be signed sighash_single or sighash_all? Shouln't leave these input/outputs unsigned
    }
}

impl BridgeTransaction for BurnTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        pre_sign_taproot_input(
            self,
            context,
            0,
            TapSighashType::Single,
            self.connector_b.generate_taproot_spend_info(),
            &vec![&n_of_n_keypair],
        );
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction {
        if (self.tx.output.len() < 2) {
            panic!("Missing output. Call add_output before finalizing");
        }

        self.tx.clone()
    }
}
