use crate::{bridge::graph::DEPOSITOR_SECRET, treepp::*};
use bitcoin::{
    absolute, key::Keypair, secp256k1::Message, sighash::{Prevouts, SighashCache}, taproot::LeafVersion, Amount, OutPoint, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT, N_OF_N_SECRET, OPERATOR_SECRET};

use super::bridge::*;
use super::connector_a::*;
use super::helper::*;

pub struct ChallengeTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    input_amount_crowdfunding: Amount,
}

impl ChallengeTransaction {
  pub fn new(context: &BridgeContext, input0: Input, input_amount_crowdfunding: Amount) -> Self {
        let depositor_public_key = context
            .depositor_public_key
            .expect("operator_public_key is required in context");

        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let operator_taproot_public_key = context
            .operator_taproot_public_key
            .expect("operator_taproot_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let _input0 = TxIn {
            previous_output: input0.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _input1 = TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount = input0.amount + input_amount_crowdfunding - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(&operator_public_key)
                .script_pubkey(),
        };

        ChallengeTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: generate_taproot_address(
                    &operator_taproot_public_key,
                    &n_of_n_taproot_public_key,
                )
                .script_pubkey(),
                // TODO add input1
            }],
            prev_scripts: vec![
                generate_taproot_leaf0(&operator_taproot_public_key), // TODO add input1
                generate_pay_to_pubkey_script(&depositor_public_key), // This script may not be known until it's actually mined, so it should go in finalize
            ],
            input_amount_crowdfunding,
        }
    }

    fn pre_sign_input0(
        &mut self,
        context: &BridgeContext,
        operator_keypair: &Keypair,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_keypair: &Keypair,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) {
        let input_index = 0;

        let prevouts = Prevouts::One(input_index, &self.prev_outs[input_index]);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::SinglePlusAnyoneCanPay; // TODO: shouldn't be Sighash All + AnyoneCanPay?
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), prevout_leaf.1);
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash | presign");

        let signature = context
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), operator_keypair);
        self.tx.input[input_index].witness.push(
            bitcoin::taproot::Signature {
                signature,
                sighash_type,
            }
            .to_vec(),
        );

        let spend_info =
            generate_taproot_spend_info(operator_taproot_public_key, n_of_n_taproot_public_key);
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

    fn pre_sign_input1(
        &mut self,
        context: &BridgeContext,
        operator_keypair: &Keypair,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_keypair: &Keypair,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) {
        let input_index = 1;

        let sighash_type = bitcoin::EcdsaSighashType::AllPlusAnyoneCanPay;
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(
                input_index,
                &self.prev_scripts[input_index], // TODO add script to prev_scripts
                self.prev_outs[input_index].value,
                sighash_type,
            )
            .expect("Failed to construct sighash");

        let signature = context
            .secp
            .sign_ecdsa(&Message::from(sighash), &n_of_n_keypair.secret_key());
        self.tx.input[input_index]
            .witness
            .push_ecdsa_signature(&bitcoin::ecdsa::Signature {
                signature,
                sighash_type,
            });

        self.tx.input[input_index]
            .witness
            .push(&self.prev_scripts[input_index]); // TODO to_bytes() may be needed
    }

    pub fn add_input(&mut self, context: &BridgeContext, input: OutPoint) {
        let depositor_keypair = context
          .depositor_keypair
          .expect("depositor_keypair required in context");

        let input_index = 1;

        self.tx.input[input_index].previous_output = input;

        let sighash_type = bitcoin::EcdsaSighashType::AllPlusAnyoneCanPay;
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(
                input_index,
                &self.prev_scripts[input_index],
                self.input_amount_crowdfunding,
                sighash_type,
            )
            .expect("Failed to construct sighash | add input");

        let signature = context
            .secp
            .sign_ecdsa(&Message::from(sighash), &depositor_keypair.secret_key());
      
        self.tx.input[input_index]
            .witness
            .push_ecdsa_signature(&bitcoin::ecdsa::Signature {
                signature,
                sighash_type,
            });

        self.tx.input[input_index]
            .witness
            .push(&self.prev_scripts[input_index]); // TODO to_bytes() may be needed
    }
}

impl BridgeTransaction for ChallengeTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key required in context");

        let operator_keypair = context
            .operator_keypair
            .expect("operator_keypair is required in context");

        let operator_taproot_public_key = context
            .operator_taproot_public_key
            .expect("operator_taproot_public_key is required in context");

        self.pre_sign_input0(
            context,
            &operator_keypair,
            &operator_taproot_public_key,
            &n_of_n_keypair,
            &n_of_n_taproot_public_key,
        );

        // QUESTION How do we pre-sign input1?
        // self.pre_sign_input1(
        //     context,
        //     &operator_keypair,
        //     &operator_taproot_public_key,
        //     &n_of_n_keypair,
        //     &n_of_n_taproot_public_key,
        // );
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        self.tx.clone()
    }
}
