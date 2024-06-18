use std::str::FromStr;

use crate::treepp::*;
use bitcoin::PrivateKey;
use bitcoin::{
    absolute, key::Keypair, secp256k1::Message, sighash::SighashCache, Amount, Network, PublicKey,
    Sequence, Transaction, TxIn, TxOut, Witness,
};

use super::super::context::BridgeContext;
use super::super::graph::FEE_AMOUNT;

use super::bridge::*;
use super::connector_z::*;
use super::helper::*;

pub struct PegInDepositTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    evm_address: String,
}

impl PegInDepositTransaction {
    pub fn new(context: &BridgeContext, input0: Input, evm_address: String) -> Self {
        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let depositor_public_key = context
            .depositor_public_key
            .expect("depositor_public_key is required in context");

        let depositor_taproot_public_key = context
            .depositor_taproot_public_key
            .expect("depositor_taproot_public_key is required in context");

        let _input0 = TxIn {
            previous_output: input0.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_taproot_address(
                &evm_address,
                &n_of_n_taproot_public_key,
                &depositor_taproot_public_key,
            )
            .script_pubkey(),
        };

        PegInDepositTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: generate_pay_to_pubkey_script_address(&depositor_public_key)
                    .script_pubkey(),
            }], // TODO
            prev_scripts: vec![generate_pay_to_pubkey_script(&depositor_public_key)], // TODO
            evm_address,
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, depositor_keypair: &Keypair) {
        let input_index = 0;

        let sighash_type = bitcoin::EcdsaSighashType::All;
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(
                input_index,
                &self.prev_scripts[input_index],
                self.prev_outs[input_index].value,
                sighash_type,
            )
            .expect("Failed to construct sighash");

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

impl BridgeTransaction for PegInDepositTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let depositor_keypair = context
            .depositor_keypair
            .expect("depositor_keypair is required in context");

        self.pre_sign_input0(context, &depositor_keypair);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        // TODO n-of-n finish presign leaf1
        self.tx.clone()
    }
}
