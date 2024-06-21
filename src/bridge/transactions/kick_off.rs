use crate::treepp::*;
use bitcoin::{absolute, Amount, Sequence, Transaction, TxIn, TxOut, Witness};

use super::{
    super::{
        connectors::{
            connector::*, connector_1::Connector1, connector_a::ConnectorA, connector_b::ConnectorB,
        },
        context::BridgeContext,
        graph::{DUST_AMOUNT, FEE_AMOUNT},
        scripts::*,
    },
    bridge::*,
    signing::*,
};

pub struct KickOffTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl KickOffTransaction {
    pub fn new(context: &BridgeContext, operator_input: Input) -> Self {
        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let operator_taproot_public_key = context
            .operator_taproot_public_key
            .expect("operator_taproot_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_1 = Connector1::new(context.network, &operator_public_key);
        let connector_a = ConnectorA::new(
            context.network,
            &operator_taproot_public_key,
            &n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(context.network, &n_of_n_taproot_public_key);

        // TODO: Include commit y
        // TODO: doesn't that mean we need to include an inscription for commit Y, so we need another TXN before this one?
        let _input0 = TxIn {
            previous_output: operator_input.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let available_input_amount = operator_input.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_1.generate_address().script_pubkey(),
        };

        let _output1 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
        };

        let _output2 = TxOut {
            value: available_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        };

        KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![TxOut {
                value: operator_input.amount,
                script_pubkey: generate_p2wpkh_address(context.network, &operator_public_key)
                    .script_pubkey(), // TODO: Add address of Commit y
            }],
            prev_scripts: vec![
                // TODO: Add the script for Commit y
            ],
        }
    }
}

impl BridgeTransaction for KickOffTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        // No-op - There's no pre-sign step for the Kick-off tx. Consider not implementing BridgeTransaction for
        // KickOffTransaction to remove the confusion that, like the other txs, it is pre-signed and shared with
        // verifiers to implement the bridge. Instead, we can implement just the finalize function.
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        let mut tx = self.tx.clone();

        let operator_keypair = context
            .operator_keypair
            .expect("operator_key is required in context");
        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let input_index = 0;
        let sighash_type = bitcoin::EcdsaSighashType::All;
        let value = self.prev_outs[input_index].value;
        populate_p2wpkh_witness(
            context,
            &mut tx,
            input_index,
            sighash_type,
            value,
            &operator_public_key,
            &operator_keypair,
        );

        tx
    }
}
