use crate::treepp::*;
use serde::{Deserialize, Serialize};
use bitcoin::{
    absolute, key::Keypair, sighash::Prevouts, Amount, TapSighashType, Transaction, TxOut, consensus
};

use super::{
    super::{
        connectors::{connector::*, connector_z::ConnectorZ},
        context::BridgeContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    bridge::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PegInRefundTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_z: ConnectorZ,
}

impl PegInRefundTransaction {
    pub fn new(context: &BridgeContext, input0: Input, evm_address: String) -> Self {
        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let depositor_public_key = context
            .depositor_public_key
            .expect("depositor_public_key is required in context");

        let depositor_taproot_public_key = context
            .depositor_taproot_public_key
            .expect("depositor_taproot_public_key is required in context");

        let connector_z = ConnectorZ::new(
            context.network,
            &evm_address,
            &depositor_taproot_public_key,
            &n_of_n_taproot_public_key,
        );

        let _input0 = connector_z.generate_taproot_leaf_tx_in(0, &input0);

        let total_output_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(
                context.network,
                &depositor_public_key,
            )
            .script_pubkey(),
        };

        PegInRefundTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_z.generate_taproot_leaf_script(0)],
            connector_z,
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, depositor_keypair: &Keypair) {
        let input_index = 0;
        let prevouts = Prevouts::All(&self.prev_outs);
        let sighash_type = TapSighashType::All;
        let script = &self.prev_scripts[input_index];
        let taproot_spend_info = self.connector_z.generate_taproot_spend_info();

        populate_taproot_input_witness(
            context,
            &mut self.tx,
            &prevouts,
            input_index,
            sighash_type,
            &taproot_spend_info,
            script,
            &vec![&depositor_keypair],
        );
    }
}

impl BridgeTransaction for PegInRefundTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let depositor_keypair = context
            .depositor_keypair
            .expect("depositor_keypair is required in context");

        self.pre_sign_input0(context, &depositor_keypair);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { self.tx.clone() }
}
