use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            connector::*, connector_1::Connector1, connector_a::ConnectorA, connector_b::ConnectorB,
        },
        contexts::operator::OperatorContext,
        graphs::base::{DUST_AMOUNT, FEE_AMOUNT},
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct KickOffTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for KickOffTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl KickOffTransaction {
    pub fn new(context: &OperatorContext, operator_input: Input) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            operator_input,
        );

        this.sign_input0(context);

        this
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_input: Input,
    ) -> Self {
        let connector_1 = Connector1::new(network, operator_public_key);
        let connector_a = ConnectorA::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(network, n_of_n_taproot_public_key);

        // TODO: Include commit y
        // TODO: doesn't that mean we need to include an inscription for commit Y, so we need another TXN before this one?
        let _input0 = TxIn {
            previous_output: operator_input.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let available_input_amount = operator_input.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_1.generate_address().script_pubkey(),
        };

        let _output1 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
        };

        let _output2 = TxOut {
            value: available_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
        };

        KickOffTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![TxOut {
                value: operator_input.amount,
                script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                    .script_pubkey(), // TODO: Add address of Commit y
            }],
            prev_scripts: vec![generate_pay_to_pubkey_script(operator_public_key)],
        }
    }

    fn sign_input0(&mut self, context: &OperatorContext) {
        pre_sign_p2wsh_input(
            self,
            context,
            0,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }
}

impl BaseTransaction for KickOffTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
