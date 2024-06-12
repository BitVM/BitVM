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
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let operator_pubkey = context
            .operator_pubkey
            .expect("operator_pubkey is required in context");
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");

        // TODO: Include commit y
        let _input0 = TxIn {
            previous_output: input0.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: generate_timelock_script_address(&n_of_n_pubkey, 2).script_pubkey(),
        };

        let _output1 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: super::connector_a::generate_address(&operator_pubkey, &n_of_n_pubkey)
                .script_pubkey(),
        };

        let _output2 = TxOut {
            value: input0.1 - Amount::from_sat(FEE_AMOUNT),
            script_pubkey: super::connector_b::generate_address(&n_of_n_pubkey).script_pubkey(),
        };

        KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![],
            prev_scripts: vec![],
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

// Currently only connector B.
pub fn generate_kickoff_leaves(
    n_of_n_pubkey: XOnlyPublicKey,
    operator_pubkey: XOnlyPublicKey,
) -> Vec<ScriptBuf> {
    // TODO: Single script with n_of_n_pubkey (Does something break if we don't sign with
    // operator_key?). Spendable by revealing all commitments
    todo!()
}
