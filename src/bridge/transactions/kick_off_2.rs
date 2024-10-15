use bitcoin::{
    absolute, consensus, Amount, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
    XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::bridge::{
    connectors::base::{CommitmentConnector, P2wshConnector, TaprootConnector},
    transactions::signing_winternitz::WinternitzSecret,
};

use super::{
    super::{
        connectors::{connector_1::Connector1, connector_3::Connector3, connector_b::ConnectorB},
        contexts::operator::OperatorContext,
        graphs::base::DUST_AMOUNT,
    },
    base::*,
    pre_signed::*,
    signing::{generate_taproot_leaf_schnorr_signature, populate_taproot_input_witness},
};

const MIN_RELAY_FEE_AMOUNT: u64 = 52_953;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct KickOff2Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for KickOff2Transaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl KickOff2Transaction {
    pub fn new(context: &OperatorContext, connector_1: &Connector1, input_0: Input) -> Self {
        Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.n_of_n_taproot_public_key,
            connector_1,
            input_0,
        )
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        connector_1: &Connector1,
        input_0: Input,
    ) -> Self {
        let connector_3 = Connector3::new(network, operator_public_key);
        let connector_b = ConnectorB::new(network, n_of_n_taproot_public_key);

        let input_0_leaf = 0;
        let _input_0 = connector_1.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(MIN_RELAY_FEE_AMOUNT);

        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_3.generate_address().script_pubkey(),
        };

        let _output_1 = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        };

        KickOff2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0, _output_1],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_1.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_1.generate_taproot_leaf_script(input_0_leaf)],
        }
    }

    pub fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        connector_1: &Connector1,
        winternitz_secret: &WinternitzSecret,
        message: &[u8],
    ) {
        let input_index = 0;
        let prev_outs = &self.prev_outs().clone();
        let script = &self.prev_scripts()[input_index].clone();
        let taproot_spend_info = connector_1.generate_taproot_spend_info();
        let mut unlock_data: Vec<Vec<u8>> = Vec::new();

        let schnorr_signature = generate_taproot_leaf_schnorr_signature(
            context,
            self.tx_mut(),
            prev_outs,
            input_index,
            TapSighashType::All,
            script,
            &context.operator_keypair,
        );
        unlock_data.push(schnorr_signature.to_vec());

        let leaf_index = 0;
        let winternitz_signatures =
            connector_1.generate_commitment_witness(leaf_index, winternitz_secret, message);
        for winternitz_signature in winternitz_signatures {
            unlock_data.push(winternitz_signature);
        }

        populate_taproot_input_witness(
            self.tx_mut(),
            input_index,
            &taproot_spend_info,
            script,
            unlock_data,
        );
    }
}

impl BaseTransaction for KickOff2Transaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
