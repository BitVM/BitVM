use crate::treepp::*;
use bitcoin::{
    absolute,
    key::Keypair,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Amount, Network, TapLeafHash, TapSighashType, Transaction, TxOut,
};

use super::{
    super::context::BridgeContext, super::graph::FEE_AMOUNT, bridge::*, connector_0::Connector0,
    connector_1::Connector1, connector_a::ConnectorA, connector_b::ConnectorB, helper::*,
};

pub struct Take1Transaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_a: ConnectorA,
    connector_b: ConnectorB,
}

impl Take1Transaction {
    pub fn new(
        context: &BridgeContext,
        input0: Input,
        input1: Input,
        input2: Input,
        input3: Input,
    ) -> Self {
        let operator_public_key = context
            .operator_public_key
            .expect("operator_public_key is required in context");

        let operator_taproot_public_key = context
            .operator_taproot_public_key
            .expect("operator_taproot_public_key is required in context");

        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_0 = Connector0::new(Network::Testnet, &n_of_n_public_key);
        let connector_1 = Connector1::new(Network::Testnet, &operator_public_key);
        let connector_a = ConnectorA::new(
            Network::Testnet,
            &operator_taproot_public_key,
            &n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(Network::Testnet, &n_of_n_taproot_public_key);

        let _input0 = connector_0.generate_script_tx_in(&input0);

        let _input1 = connector_1.generate_script_tx_in(&input1);

        let _input2 = connector_a.generate_taproot_leaf0_tx_in(&input2);

        let _input3 = connector_b.generate_taproot_leaf0_tx_in(&input3);

        let total_input_amount = input0.amount + input1.amount + input2.amount + input3.amount
            - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(context.network, &operator_public_key)
                .script_pubkey(),
        };

        Take1Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1, _input2, _input3],
                output: vec![_output0],
            },
            prev_outs: vec![
                TxOut {
                    value: input0.amount,
                    script_pubkey: connector_0.generate_script_address().script_pubkey(),
                },
                TxOut {
                    value: input1.amount,
                    script_pubkey: connector_1.generate_script_address().script_pubkey(),
                },
                TxOut {
                    value: input2.amount,
                    script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input3.amount,
                    script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_script(),
                connector_1.generate_script(),
                connector_a.generate_taproot_leaf0(),
                connector_b.generate_taproot_leaf0(),
            ],
            connector_a,
            connector_b,
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

    fn pre_sign_input2(&mut self, context: &BridgeContext, operator_keypair: &Keypair) {
        let input_index = 2;

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::All;
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), prevout_leaf.1);
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

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

        let spend_info = self.connector_a.generate_taproot_spend_info();
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");
        self.tx.input[input_index]
            .witness
            .push(prevout_leaf.0.to_bytes()); // TODO to_bytes() may NOT be needed
        self.tx.input[input_index]
            .witness
            .push(control_block.serialize());
    }

    fn pre_sign_input3(&mut self, context: &BridgeContext, n_of_n_keypair: &Keypair) {
        let input_index = 3;

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::All;
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

        let spend_info = self.connector_b.generate_taproot_spend_info();
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

impl BridgeTransaction for Take1Transaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        let operator_keypair = context
            .operator_keypair
            .expect("operator_keypair required in context");

        self.pre_sign_input0(context, &n_of_n_keypair);
        self.pre_sign_input1(context, &n_of_n_keypair);
        self.pre_sign_input2(context, &operator_keypair);
        self.pre_sign_input3(context, &n_of_n_keypair);
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction {
        self.tx.clone()
    }
}
