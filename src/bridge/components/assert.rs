use crate::treepp::*;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::LeafVersion;
use bitcoin::{
    absolute, Amount, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness,
};
use musig2::secp256k1::Message;

use super::super::context::BridgeContext;
use super::super::graph::{DUST_AMOUNT, FEE_AMOUNT};

use super::bridge::*;
use super::helper::*;

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let _input0 = TxIn {
            previous_output: input0.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: generate_timelock_script_address(&n_of_n_public_key, 2).script_pubkey(),
        };

        let _output1 = TxOut {
            value: total_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: super::connector_c::generate_taproot_pre_sign_address(
                &n_of_n_taproot_public_key,
            )
            .script_pubkey(),
        };

        let _output2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: super::connector_c::generate_taproot_address(&n_of_n_taproot_public_key)
                .script_pubkey(),
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
                script_pubkey: super::connector_b::generate_taproot_address(
                    &n_of_n_taproot_public_key,
                )
                .script_pubkey(),
            }],
            prev_scripts: vec![super::connector_b::generate_taproot_leaf1(
                &n_of_n_taproot_public_key,
            )],
        }
    }
}

impl BridgeTransaction for AssertTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key required in context");
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        let mut sighash_cache = SighashCache::new(&self.tx);
        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (self.prev_scripts[0].clone(), LeafVersion::TapScript);

        let sighash_type = TapSighashType::All;
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), LeafVersion::TapScript);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let msg = Message::from(sighash);
        let signature = context.secp.sign_schnorr_no_aux_rand(&msg, &n_of_n_keypair);

        let signature_with_type = bitcoin::taproot::Signature {
            signature,
            sighash_type,
        };

        // Fill in the pre_sign/checksig input's witness
        let spend_info =
            super::connector_b::generate_taproot_spend_info(&n_of_n_taproot_public_key);
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");
        self.tx.input[0].witness.push(signature_with_type.to_vec());
        self.tx.input[0].witness.push(prevout_leaf.0.to_bytes());
        self.tx.input[0].witness.push(control_block.serialize());
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction { self.tx.clone() }
}
