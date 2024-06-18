use crate::treepp::*;
use bitcoin::{
    absolute,
    key::Keypair,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Amount, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};

use super::super::context::BridgeContext;
use super::super::graph::FEE_AMOUNT;

use super::bridge::*;
use super::connector_c::*;
use super::helper::*;
pub struct DisproveTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    script_index: u32,
}

impl DisproveTransaction {
    pub fn new(
        context: &BridgeContext,
        pre_sign_input: Input,
        connector_c_input: Input,
        script_index: u32,
    ) -> Self {
        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let _input0 = TxIn {
            previous_output: pre_sign_input.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _input1 = TxIn {
            previous_output: connector_c_input.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount =
            pre_sign_input.amount + connector_c_input.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount / 2,
            script_pubkey: generate_burn_script_address().script_pubkey(),
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
                    script_pubkey: generate_taproot_pre_sign_address(&n_of_n_taproot_public_key)
                        .script_pubkey(),
                },
                TxOut {
                    value: connector_c_input.amount,
                    script_pubkey: generate_taproot_address(&n_of_n_taproot_public_key)
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![generate_taproot_pre_sign_leaf0(&n_of_n_taproot_public_key)],
            script_index,
        }
    }

    fn pre_sign_input0(
        &mut self,
        context: &BridgeContext,
        n_of_n_keypair: &Keypair,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) {
        let input_index = 0;

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::Single;
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), prevout_leaf.1);
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let signature = context
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), n_of_n_keypair); // This is where all n of n verifiers will sign
        self.tx.input[input_index].witness.push(
            bitcoin::taproot::Signature {
                signature,
                sighash_type,
            }
            .to_vec(),
        );

        let spend_info = generate_taproot_spend_info(n_of_n_taproot_public_key).0;
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");
        self.tx.input[input_index]
            .witness
            .push(prevout_leaf.0.to_bytes());
        self.tx.input[input_index]
            .witness
            .push(control_block.serialize());
    }
}

impl BridgeTransaction for DisproveTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        self.pre_sign_input0(context, &n_of_n_keypair, &n_of_n_taproot_public_key);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        let input_index = 1;

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let prevout_leaf = (
            (assert_leaf().lock)(self.script_index),
            LeafVersion::TapScript,
        );
        let spend_info = generate_taproot_spend_info(&n_of_n_taproot_public_key).1;
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");

        // Push the unlocking values, script and control_block onto the witness.
        let mut tx = self.tx.clone();
        // Unlocking script
        let mut witness_vec = (assert_leaf().unlock)(self.script_index);
        // Script and Control block
        witness_vec.extend_from_slice(&[prevout_leaf.0.to_bytes(), control_block.serialize()]);

        tx.input[input_index].witness = Witness::from(witness_vec);
        tx
    }
}
