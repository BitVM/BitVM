use crate::treepp::*;
use bitcoin::{
    absolute, key::Keypair, secp256k1::Message, sighash::{Prevouts, SighashCache}, taproot::LeafVersion, Amount, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT, N_OF_N_SECRET};

use super::bridge::*;
use super::connector_c::*;
use super::helper::*;
pub struct DisproveTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    script_index: u32,
}

impl DisproveTransaction {
    pub fn new(
        context: &BridgeContext,
        pre_sign_input: Input,
        connector_c_input: Input,
        script_index: u32,
    ) -> Self {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let _input0 = TxIn {
            previous_output: pre_sign_input.0,
            script_sig: Script::new(), // Question: Why is this empty? Is it because it's using segwit?
            sequence: Sequence::MAX,
            witness: Witness::default(), // Question: This gets filled in during pre-sign and finalize later
        };

        let _input1 = TxIn {
            previous_output: connector_c_input.0,
            script_sig: Script::new(), // Question: Why is this empty? IS it because it's using segwit?
            sequence: Sequence::MAX,
            witness: Witness::default(), // Question: This gets filled in during pre-sign and finalize later
        };

        let total_input_amount = pre_sign_input.1 + connector_c_input.1 - Amount::from_sat(FEE_AMOUNT); // Question: What is this fee?

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
                    value: pre_sign_input.1,
                    script_pubkey: generate_pre_sign_address(&n_of_n_pubkey).script_pubkey(),
                },
                TxOut {
                    value: connector_c_input.1,
                    script_pubkey: generate_address(&n_of_n_pubkey).script_pubkey(),
                },
            ],
            script_index,
        }
    }
}

impl BridgeTransaction for DisproveTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let input_index = 0;
        let leaf_index = 0; // TODO fix this

        let n_of_n_key = Keypair::from_seckey_str(&context.secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            generate_pay_to_pubkey_script(&n_of_n_pubkey),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::Single;
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), LeafVersion::TapScript);
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(leaf_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let signature = context.secp.sign_schnorr_no_aux_rand(&Message::from(sighash), &n_of_n_key); // This is where all n of n verifiers will sign
        self.tx.input[input_index].witness.push(bitcoin::taproot::Signature {
            signature,
            sighash_type,
        }.to_vec());

        let spend_info = generate_spend_info(&n_of_n_pubkey).0;
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");
        self.tx.input[input_index].witness.push(prevout_leaf.0.to_bytes());
        self.tx.input[input_index].witness.push(control_block.serialize());
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        let input_index = 1;

        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let prevout_leaf = (
            (assert_leaf().lock)(self.script_index),
            LeafVersion::TapScript,
        );
        let spend_info = generate_spend_info(&n_of_n_pubkey).1;
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
