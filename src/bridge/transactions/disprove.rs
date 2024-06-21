use crate::treepp::*;
use bitcoin::{absolute, key::Keypair, Amount, Transaction, TxOut};

use super::{
    super::{
        connectors::{connector::*, connector_3::Connector3, connector_c::ConnectorC},
        context::BridgeContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    bridge::*,
    signing::*,
};

pub struct DisproveTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    script_index: u32,
    connector_c: ConnectorC,
}

impl DisproveTransaction {
    pub fn new(
        context: &BridgeContext,
        pre_sign_input: Input,
        connector_c_input: Input,
        script_index: u32,
    ) -> Self {
        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_3 = Connector3::new(context.network, &n_of_n_public_key);
        let connector_c = ConnectorC::new(context.network, &n_of_n_taproot_public_key);

        let _input0 = connector_3.generate_tx_in(&pre_sign_input);

        let _input1 = connector_c.generate_taproot_leaf_tx_in(script_index, &connector_c_input);

        let total_input_amount =
            pre_sign_input.amount + connector_c_input.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount / 2,
            script_pubkey: generate_burn_script_address(context.network).script_pubkey(),
        };

        DisproveTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1],
                output: vec![_output0],
            },
            prev_outs: vec![
                TxOut {
                    value: pre_sign_input.amount,
                    script_pubkey: connector_3.generate_address().script_pubkey(),
                },
                TxOut {
                    value: connector_c_input.amount,
                    script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![connector_3.generate_script()],
            script_index,
            connector_c,
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 0;
        let sighash_type = bitcoin::EcdsaSighashType::All;
        let script = &self.prev_scripts[input_index];
        let value = self.prev_outs[input_index].value;

        populate_p2wsh_witness(
            context,
            &mut self.tx,
            input_index,
            sighash_type,
            script,
            value,
            &vec![n_of_n_keypair],
        );
    }
}

impl BridgeTransaction for DisproveTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair is required in context");

        self.pre_sign_input0(context, &n_of_n_keypair);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        let mut tx = self.tx.clone();

        let input_index = 1;

        // Push the unlocking witness
        let unlock_witness = self
            .connector_c
            .generate_taproot_leaf_script_witness(self.script_index);
        tx.input[input_index].witness.push(unlock_witness);

        // Push script + control block
        let script = self
            .connector_c
            .generate_taproot_leaf_script(self.script_index);
        let taproot_spend_info = self.connector_c.generate_taproot_spend_info();
        push_taproot_leaf_script_and_control_block_to_witness(
            &mut tx,
            input_index,
            &taproot_spend_info,
            script,
        );

        tx
    }
}
