use crate::treepp::*;
use bitcoin::{absolute, consensus, Amount, EcdsaSighashType, ScriptBuf, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{connector::*, connector_z::ConnectorZ},
        contexts::depositor::DepositorContext,
        graph::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct PegInDepositTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl PreSignedTransaction for PegInDepositTransaction {
    fn tx(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> Vec<ScriptBuf> { self.prev_scripts.clone() }
}

impl PegInDepositTransaction {
    pub fn new(context: &DepositorContext, input0: Input, evm_address: String) -> Self {
        let connector_z = ConnectorZ::new(
            context.network,
            &evm_address,
            &context.depositor_taproot_public_key,
            &context.n_of_n_taproot_public_key,
        );

        let _input0 = generate_default_tx_in(&input0);

        let total_output_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount,
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
                    &context.depositor_public_key,
                )
                .script_pubkey(),
            }],
            prev_scripts: vec![generate_pay_to_pubkey_script(&context.depositor_public_key)],
        }
    }
}

impl BaseTransaction for PegInDepositTransaction {
    fn pre_sign(&mut self, context: &DepositorContext) {
        let depositor_keypair = context
            .depositor_keypair
            .expect("depositor_keypair is required in context");

        pre_sign_p2wsh_input(
            self,
            context,
            0,
            EcdsaSighashType::All,
            &vec![&depositor_keypair],
        );
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        // TODO n-of-n finish presign leaf1
        self.tx.clone()
    }
}
