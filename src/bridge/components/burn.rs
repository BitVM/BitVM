use crate::treepp::*;
use bitcoin::{
    absolute, Address, Amount, Network, Sequence, Transaction, TxIn, TxOut, Witness
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT};

use super::connector_b::*;
use super::bridge::*;
use super::helper::*;
pub struct BurnTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl BurnTransaction {
    pub fn new(
        context: &BridgeContext,
        input0: Input,
    ) -> Self {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let _input0 = TxIn {
            previous_output: input0.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount = input0.1 - Amount::from_sat(FEE_AMOUNT);

        // Output[0]: value=V*2%*95% to burn
        let _output0 = TxOut {
            value: total_input_amount * 95 / 100,
            script_pubkey: Address::p2sh(&generate_burn_script(), Network::Testnet).expect("Unable to generate output script").script_pubkey(),
        };

        // Output[1]: value=V*2%*5% to anyone
        let _output1 = TxOut {
            value: total_input_amount - (total_input_amount * 5 / 100),
            script_pubkey: Script::new() // TODO fill in
        };

        BurnTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1],
            },
            prev_outs: vec![
                TxOut {
                    value: input0.1,
                    script_pubkey: generate_address(&n_of_n_pubkey).script_pubkey(),
                },
            ],
            prev_scripts: vec![
                generate_leaf2(&n_of_n_pubkey)
            ]
        }
    }
}

impl BridgeTransaction for BurnTransaction {
    //TODO: Real presign
    fn pre_sign(&mut self, context: &BridgeContext) {
    //     let n_of_n_key = Keypair::from_seckey_str(&context.secp, N_OF_N_SECRET).unwrap();
    //     let n_of_n_pubkey = context
    //         .n_of_n_pubkey
    //         .expect("n_of_n_pubkey required in context");

    //     // Create the signature with n_of_n_key as part of the setup
    //     let mut sighash_cache = SighashCache::new(&self.tx);
    //     let prevouts = Prevouts::All(&self.prev_outs);
    //     let prevout_leaf = (
    //         generate_pay_to_pubkey_script(n_of_n_pubkey),
    //         LeafVersion::TapScript,
    //     );

    //     // Use Single to sign only the burn output with the n_of_n_key
    //     let sighash_type = TapSighashType::Single;
    //     let leaf_hash =
    //         TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), LeafVersion::TapScript);
    //     let sighash = sighash_cache
    //         .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
    //         .expect("Failed to construct sighash");

    //     let signature = context.secp.sign_schnorr_no_aux_rand(&Message::from(sighash), &n_of_n_key);
    //     self.tx.input[0].witness.push(bitcoin::taproot::Signature {
    //         signature,
    //         sighash_type,
    //     }.to_vec());

    //     // Fill in the pre_sign/checksig input's witness
    //     let spend_info = connector_b_spend_info(n_of_n_pubkey);
    //     let control_block = spend_info
    //         .control_block(&prevout_leaf)
    //         .expect("Unable to create Control block");
    //     self.tx.input[0].witness.push(prevout_leaf.0.to_bytes());
    //     self.tx.input[0].witness.push(control_block.serialize());
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        // TODO fill in proper tx info

        // let prevout_leaf = (
        //     (assert_leaf().lock)(self.script_index),
        //     LeafVersion::TapScript,
        // );
        // let spend_info = connector_b_spend_info(n_of_n_pubkey).1;
        // let control_block = spend_info
        //     .control_block(&prevout_leaf)
        //     .expect("Unable to create Control block");

        // Push the unlocking values, script and control_block onto the witness.
        let tx = self.tx.clone();
        // // Unlocking script
        // let mut witness_vec = (assert_leaf().unlock)(self.script_index);
        // // Script and Control block
        // witness_vec.extend_from_slice(&[prevout_leaf.0.to_bytes(), control_block.serialize()]);

        // tx.input[1].witness = Witness::from(witness_vec);
        tx
    }
}
