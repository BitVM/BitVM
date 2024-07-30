use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, Transaction,
    TxOut, XOnlyPublicKey,
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
pub struct PegInDepositTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for PegInDepositTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PegInDepositTransaction {
    pub fn new(context: &DepositorContext, evm_address: &str, input0: Input) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.depositor_public_key,
            &context.depositor_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            evm_address,
            input0,
        );

        this.sign_input0(context);

        this
    }

    pub fn new_for_validation(
        network: Network,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        evm_address: &str,
        input0: Input,
    ) -> Self {
        let connector_z = ConnectorZ::new(
            network,
            evm_address,
            depositor_taproot_public_key,
            n_of_n_taproot_public_key,
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
                script_pubkey: generate_pay_to_pubkey_script_address(network, depositor_public_key)
                    .script_pubkey(),
            }],
            prev_scripts: vec![generate_pay_to_pubkey_script(depositor_public_key)],
        }
    }

    fn sign_input0(&mut self, context: &DepositorContext) {
        pre_sign_p2wsh_input(
            self,
            context,
            0,
            EcdsaSighashType::All,
            &vec![&context.depositor_keypair],
        );
    }
}

impl BaseTransaction for PegInDepositTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
