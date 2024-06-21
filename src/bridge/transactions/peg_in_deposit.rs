use crate::treepp::*;
use bitcoin::{absolute, key::Keypair, Amount, Transaction, TxOut};

use super::{
    super::{
        connectors::{connector::*, connector_z::ConnectorZ},
        context::BridgeContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    bridge::*,
    signing::*,
};

pub struct PegInDepositTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
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

        let connector_z = ConnectorZ::new(
            context.network,
            &evm_address,
            &depositor_taproot_public_key,
            &n_of_n_taproot_public_key,
        );

        let _input0 = generate_default_tx_in(&input0);

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
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
                script_pubkey: generate_pay_to_pubkey_script_address(
                    context.network,
                    &depositor_public_key,
                )
                .script_pubkey(),
            }], // TODO
            prev_scripts: vec![generate_pay_to_pubkey_script(&depositor_public_key)], // TODO
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, depositor_keypair: &Keypair) {
        let input_index = 0;
        let sighash_type = bitcoin::EcdsaSighashType::All;
        let script = &self.prev_scripts[input_index];
        let value = self.prev_outs[input_index].value;

        populate_p2wsh_witness(
            context,
            &mut self.tx,
            input_index,
            sighash_type,
            script,
            value,
            &vec![depositor_keypair],
        );
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
