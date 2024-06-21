use crate::treepp::*;
use bitcoin::{
    absolute,
    key::Keypair,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Amount, Network, Sequence, TapLeafHash, TapSighashType, Transaction, TxOut,
};

use super::{
    super::context::BridgeContext, super::graph::FEE_AMOUNT, bridge::*, connector_z::ConnectorZ,
    helper::*,
};

pub struct PegInRefundTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    evm_address: String,
    connector_z: ConnectorZ,
}

impl PegInRefundTransaction {
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

        let connector_z = ConnectorZ::new(
            Network::Testnet,
            &evm_address,
            &depositor_taproot_public_key,
            &n_of_n_taproot_public_key,
        );

        let _input0 = connector_z.generate_taproot_leaf0_tx_in(&input0);

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(
                context.network,
                &depositor_public_key,
            )
            .script_pubkey(),
        };

        PegInRefundTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_z.generate_taproot_leaf0()],
            evm_address,
            connector_z,
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, depositor_keypair: &Keypair) {
        let input_index = 0;

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::All;
        let leaf_hash = TapLeafHash::from_script(&prevout_leaf.0, prevout_leaf.1);

        let sighash = SighashCache::new(&self.tx)
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let signature = context
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), depositor_keypair);
        self.tx.input[input_index].witness.push(
            bitcoin::taproot::Signature {
                signature,
                sighash_type,
            }
            .to_vec(),
        );

        let spend_info = self.connector_z.generate_taproot_spend_info();
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

impl BridgeTransaction for PegInRefundTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let depositor_keypair = context
            .depositor_keypair
            .expect("depositor_keypair is required in context");

        self.pre_sign_input0(context, &depositor_keypair);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { self.tx.clone() }
}
