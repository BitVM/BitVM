use std::str::FromStr;

use crate::treepp::*;
use bitcoin::PrivateKey;
use bitcoin::{
    absolute,
    key::Keypair,
    secp256k1::Message,
    sighash::SighashCache,
    Amount, Sequence, Transaction, TxIn, TxOut, Witness,
    Network,
    PublicKey
};

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT, DEPOSITOR_SECRET};

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
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");
        let depositor_pubkey = context
            .depositor_pubkey
            .expect("depositor_pubkey is required in context");

        let depositor_pubkey_normal = context
            .depositor_pubkey_normal
            .expect("depositor_pubkey_normal is required in context");

        let _input0 = TxIn {
            previous_output: input0.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount = input0.1 - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_address(&evm_address, &n_of_n_pubkey, &depositor_pubkey)
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
                value: input0.1,
                script_pubkey: generate_pay_to_pubkey_script_address_normal(&depositor_pubkey_normal)
                    .script_pubkey(),
            }],    // TODO
            prev_scripts: vec![generate_pay_to_pubkey_script_normal(&depositor_pubkey_normal)], // TODO
            evm_address,
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, depositor_key: &Keypair, depositor_private_key: &PrivateKey) {
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
            .sign_ecdsa(&Message::from(sighash), &depositor_key.secret_key());
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
        // TODO presign leaf0
        // TODO depositor presign leaf1
        let depositor_key = Keypair::from_seckey_str(&context.secp, DEPOSITOR_SECRET).unwrap();
        let depositor_pubkey = depositor_key.x_only_public_key().0;
        let depositor_private_key = PrivateKey::new(depositor_key.secret_key(), Network::Testnet);
        let depositor_pubkey_normal = PublicKey::from_private_key(&context.secp, &depositor_private_key);

        self.pre_sign_input0(context, &depositor_key, &depositor_private_key);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        // TODO n-of-n finish presign leaf1
        self.tx.clone()
    }
}
