use crate::treepp::*;
use bitcoin::{
    absolute,
    Address, Amount, Network, OutPoint, Sequence,
    Transaction, TxIn, TxOut, Witness,
};

use super::super::context::BridgeContext;
use super::super::graph::FEE_AMOUNT;

use super::bridge::*;
use super::connector_c::*;

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input: OutPoint, input_value: Amount) -> Self {
        let operator_pubkey = context
            .operator_pubkey
            .expect("operator_pubkey is required in context");
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");
        let connector_c_output = TxOut {
            value: input_value - Amount::from_sat(FEE_AMOUNT),
            // TODO: This has to be KickOff transaction address
            script_pubkey: Address::p2tr_tweaked(
                connector_c_spend_info(operator_pubkey, n_of_n_pubkey).0.output_key(),
                Network::Testnet,
            )
            .script_pubkey(),
        };
        let input = TxIn {
            previous_output: input,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![input],
                output: vec![connector_c_output],
            },
            prev_outs: vec![],
        }
    }
}

impl BridgeTransaction for AssertTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        todo!();
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { todo!() }
}
