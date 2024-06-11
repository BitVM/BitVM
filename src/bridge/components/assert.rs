use crate::treepp::*;
use bitcoin::{
    absolute,
    Address, Amount, Network, Sequence,
    Transaction, TxIn, TxOut, Witness,
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT,DUST_AMOUNT};

use super::bridge::*;
use super::connector_c::*;
use super::helper::*;

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");

        let _input0 = TxIn {
            previous_output: input0.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: Address::p2wsh(
                &generate_timelock_script(n_of_n_pubkey, 2),
                Network::Testnet,
            )
            .script_pubkey(),
        };

        let _output1 = TxOut {
            value: input0.1 - Amount::from_sat(FEE_AMOUNT),
            // TODO: This has to be KickOff transaction address
            script_pubkey: Address::p2tr_tweaked(
                connector_c_spend_info(n_of_n_pubkey).0.output_key(),
                Network::Testnet,
            )
            .script_pubkey(),
        };

        let _output2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: Address::p2tr_tweaked(
                connector_c_spend_info(n_of_n_pubkey).1.output_key(),
                Network::Testnet,
            )
            .script_pubkey(),
        };

        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
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
