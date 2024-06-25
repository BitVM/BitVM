use crate::treepp::*;
use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{connector::*, connector_0::Connector0, connector_z::ConnectorZ},
        contexts::depositor::DepositorContext,
        graph::FEE_AMOUNT,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PegInConfirmTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_z: ConnectorZ,
}

impl PreSignedTransaction for PegInConfirmTransaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
}

impl PegInConfirmTransaction {
    pub fn new(context: &DepositorContext, input0: Input, evm_address: String) -> Self {
        let connector_0 = Connector0::new(context.network, &context.n_of_n_public_key);
        let connector_z = ConnectorZ::new(
            context.network,
            &evm_address,
            &context.depositor_taproot_public_key,
            &context.n_of_n_taproot_public_key,
        );

        let _input0 = connector_z.generate_taproot_leaf_tx_in(1, &input0);

        let total_output_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_0.generate_address().script_pubkey(),
        };

        PegInConfirmTransaction {
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
            prev_scripts: vec![connector_z.generate_taproot_leaf_script(1)],
            connector_z,
        }
    }
}

impl BaseTransaction for PegInConfirmTransaction {
    fn pre_sign(&mut self, context: &dyn BaseContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair is required in context");

        let depositor_keypair = context
            .depositor_keypair
            .expect("depositor_keypair is required in context");

        pre_sign_taproot_input(
            self,
            context,
            0,
            TapSighashType::All,
            self.connector_z.generate_taproot_spend_info(),
            &vec![&depositor_keypair, &n_of_n_keypair],
        );
    }

    fn finalize(&self, _context: &BaseContext) -> Transaction { self.tx.clone() }
}
