use crate::treepp::*;
use bitcoin::{
    absolute, key::Keypair, sighash::Prevouts, Amount, TapSighashType, Transaction, TxOut,
};

use super::{
    super::{
        connectors::{
            connector::*,
            connector_2::Connector2,
            connector_3::Connector3,
            connector_b::ConnectorB,
            connector_c::ConnectorC,
        },
        context::BridgeContext,
        graph::{DUST_AMOUNT, FEE_AMOUNT},
    },
    bridge::*,
    signing::*,
};

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_b: ConnectorB,
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_2 = Connector2::new(context.network, &n_of_n_public_key);
        let connector_3 = Connector3::new(context.network, &n_of_n_public_key);
        let connector_b = ConnectorB::new(context.network, &n_of_n_taproot_public_key);
        let connector_c = ConnectorC::new(context.network, &n_of_n_taproot_public_key);

        let _input0 = connector_b.generate_taproot_leaf_tx_in(1, &input0);

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_2.generate_address().script_pubkey(),
        };

        let _output1 = TxOut {
            value: total_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
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

    fn pre_sign_input0(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 0;
        let prevouts = Prevouts::All(&self.prev_outs);
        let sighash_type = TapSighashType::All;
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

impl BridgeTransaction for AssertTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        self.pre_sign_input0(context, &n_of_n_keypair);
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction { self.tx.clone() }
}
