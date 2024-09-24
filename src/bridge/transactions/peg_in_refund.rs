use bitcoin::{
    absolute, consensus, Amount, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
    XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{connector::*, connector_z::ConnectorZ},
        contexts::depositor::DepositorContext,
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInRefundTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_z: ConnectorZ,
}

impl PreSignedTransaction for PegInRefundTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PegInRefundTransaction {
    pub fn new(context: &DepositorContext, evm_address: &str, input_0: Input) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.depositor_public_key,
            &context.depositor_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            evm_address,
            input_0,
        );

        this.sign_input_0(context);

        this
    }

    pub fn new_for_validation(
        network: Network,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        evm_address: &str,
        input_0: Input,
    ) -> Self {
        let connector_z = ConnectorZ::new(
            network,
            evm_address,
            depositor_taproot_public_key,
            n_of_n_taproot_public_key,
        );

        let input_0_leaf = 0;
        let _input_0 = connector_z.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(network, depositor_public_key)
                .script_pubkey(),
        };

        PegInRefundTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_z.generate_taproot_leaf_script(input_0_leaf)],
            connector_z,
        }
    }

    pub fn num_blocks_timelock_0(&self) -> u32 { self.connector_z.num_blocks_timelock_0 }

    fn sign_input_0(&mut self, context: &DepositorContext) {
        pre_sign_taproot_input_default(
            self,
            context,
            0,
            TapSighashType::All,
            self.connector_z.generate_taproot_spend_info(),
            &vec![&context.depositor_keypair],
        );
    }
}

impl BaseTransaction for PegInRefundTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
