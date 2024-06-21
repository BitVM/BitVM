use crate::treepp::*;
use bitcoin::{
    absolute, key::Keypair, sighash::Prevouts, Amount, TapSighashType, Transaction, TxOut,
};

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

pub struct BurnTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_b: ConnectorB,
}

impl BurnTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_b = ConnectorB::new(context.network, &n_of_n_taproot_public_key);

        let _input0 = connector_b.generate_taproot_leaf_tx_in(2, &input0);

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        // Output[0]: value=V*2%*95% to burn
        let _output0 = TxOut {
            value: total_input_amount * 95 / 100,
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
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 0;
        let prevouts = Prevouts::All(&self.prev_outs);
        let sighash_type = TapSighashType::Single;
        let script = &self.prev_scripts[input_index];
        let taproot_spend_info = self.connector_b.generate_taproot_spend_info();

        populate_taproot_input_witness(
            context,
            &mut self.tx,
            &prevouts,
            input_index,
            sighash_type,
            &taproot_spend_info,
            script,
            &vec![&n_of_n_keypair],
        );
    }
}

impl BridgeTransaction for BurnTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        self.pre_sign_input0(context, &n_of_n_keypair);
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction { self.tx.clone() }
}
