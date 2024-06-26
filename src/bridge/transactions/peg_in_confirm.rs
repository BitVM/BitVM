use crate::{bridge::contexts::verifier::VerifierContext, treepp::*};
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
    signing::*,
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

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
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

        let mut this = PegInConfirmTransaction {
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
        };

        this.push_depositor_signature_input0(context);

        this
    }

    fn push_depositor_signature_input0(&mut self, context: &DepositorContext) {
        let input_index = 0;
        push_taproot_leaf_signature_to_witness(
            context,
            &mut self.tx,
            &self.prev_outs,
            input_index,
            TapSighashType::All,
            &self.prev_scripts[input_index],
            &context.depositor_keypair,
        );
    }

    fn push_n_of_n_signature_input0(&mut self, context: &VerifierContext) {
        let input_index = 0;
        push_taproot_leaf_signature_to_witness(
            context,
            &mut self.tx,
            &self.prev_outs,
            input_index,
            TapSighashType::All,
            &self.prev_scripts[input_index],
            &context.n_of_n_keypair,
        );
    }

    fn finalize_input0(&mut self) {
        let input_index = 0;
        push_taproot_leaf_script_and_control_block_to_witness(
            &mut self.tx,
            input_index,
            &self.connector_z.generate_taproot_spend_info(),
            &self.prev_scripts[input_index],
        );
    }

    pub fn pre_sign(&mut self, context: &VerifierContext) {
        self.push_n_of_n_signature_input0(context);
    }
}

impl BaseTransaction for PegInConfirmTransaction {
    fn finalize(&mut self) -> Transaction {
        self.finalize_input0();
        self.tx.clone()
    }
}
