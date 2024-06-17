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
    pub fn new(context: &BridgeContext, operator_input: Input, operator_input_witness: Witness) -> Self {
        let operator_pubkey = context
            .operator_pubkey
            .expect("operator_pubkey is required in context");
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");

        // TODO: Include commit y
        // TODO: doesn't that mean we need to include an inscription for commit Y, so we need another TXN before this one?
        let input0 = TxIn {
            previous_output: operator_input.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: operator_input_witness,
        };

        let output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: generate_timelock_script_address(&operator_pubkey, 2).script_pubkey(),
        };
            
        let output1 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: super::connector_a::generate_address(&operator_pubkey, &n_of_n_pubkey).script_pubkey(),
        };
                
        let available_input_amount = operator_input.amount - Amount::from_sat(FEE_AMOUNT);
        let output2 = TxOut {
            value: available_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: super::connector_b::generate_address(&n_of_n_pubkey).script_pubkey(),
        };

        KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![input0],
                output: vec![output0, output1, output2],
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
