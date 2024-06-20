use crate::treepp::*;
use bitcoin::{
    absolute, key::Keypair, secp256k1::Message, sighash::SighashCache, Amount, Network,
    Transaction, TxOut,
};

use super::{
    super::context::BridgeContext, super::graph::FEE_AMOUNT, bridge::*, connector_0::Connector0,
    connector_2::Connector2, connector_3::Connector3, helper::*,
};

pub struct Take2Transaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl Take2Transaction {
    pub fn new(context: &BridgeContext, input0: Input, input1: Input, input2: Input) -> Self {
        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let connector_0 = Connector0::new(Network::Testnet, &n_of_n_public_key);
        let connector_2 = Connector2::new(Network::Testnet, &n_of_n_public_key);
        let connector_3 = Connector3::new(Network::Testnet, &n_of_n_public_key);

        let _input0 = connector_0.generate_script_tx_in(&input0);

        let _input1 = connector_2.generate_script_tx_in(&input1);

        let _input2 = connector_3.generate_script_tx_in(&input2);

        let total_input_amount =
            input0.amount + input1.amount + input2.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(&operator_public_key, context.network)
                .script_pubkey(),
        };

        Take2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1, _input2],
                output: vec![_output0],
            },
            prev_outs: vec![
                TxOut {
                    value: input0.amount,
                    script_pubkey: connector_0.generate_script_address().script_pubkey(),
                },
                TxOut {
                    value: input1.amount,
                    script_pubkey: connector_2.generate_script_address().script_pubkey(),
                },
                TxOut {
                    value: input2.amount,
                    script_pubkey: connector_3.generate_script_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_script(),
                connector_2.generate_script(),
                connector_3.generate_script(),
            ],
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
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

    fn pre_sign_input1(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 1;

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

    fn pre_sign_input2(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 2;

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
}

impl BridgeTransaction for Take2Transaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair is required in context");

        self.pre_sign_input0(context, &n_of_n_keypair);
        self.pre_sign_input1(context, &n_of_n_keypair);
        self.pre_sign_input2(context, &n_of_n_keypair);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        self.tx.clone()
    }
}
