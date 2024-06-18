use crate::treepp::*;
use bitcoin::{
    absolute, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};

use super::super::context::BridgeContext;
use super::super::graph::{DUST_AMOUNT, FEE_AMOUNT};

use super::bridge::*;
use super::helper::*;

pub struct KickOffTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl KickOffTransaction {
    pub fn new(
        context: &BridgeContext,
        operator_input: Input,
        operator_input_witness: Witness,
    ) -> Self {
        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let operator_taproot_public_key = context
            .operator_taproot_public_key
            .expect("operator_taproot_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        // TODO: Include commit y
        // TODO: doesn't that mean we need to include an inscription for commit Y, so we need another TXN before this one?
        let _input0 = TxIn {
            previous_output: operator_input.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: operator_input_witness,
        };

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: generate_timelock_script_address(&operator_public_key, 2)
                .script_pubkey(),
        };

        let _output1 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: super::connector_a::generate_taproot_address(
                &operator_taproot_public_key,
                &n_of_n_taproot_public_key,
            )
            .script_pubkey(),
        };

        let available_input_amount = operator_input.amount - Amount::from_sat(FEE_AMOUNT);

        let _output2 = TxOut {
            value: available_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: super::connector_b::generate_taproot_address(&n_of_n_taproot_public_key)
                .script_pubkey(),
        };

        KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![
                // TODO
            ],
            prev_scripts: vec![
                // TODO
            ],
        }
    }
}

impl BridgeTransaction for KickOffTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        todo!();
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        todo!()
    }
}
