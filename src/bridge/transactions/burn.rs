use bitcoin::{absolute, consensus, Amount, ScriptBuf, TapSighashType, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{connector::*, connector_b::ConnectorB},
        contexts::{operator::OperatorContext, verifier::VerifierContext},
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct BurnTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_b: ConnectorB,
    reward_output_amount: Amount,
}

impl PreSignedTransaction for BurnTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl BurnTransaction {
    pub fn new(context: &OperatorContext, input0: Input) -> Self {
        let connector_b = ConnectorB::new(context.network, &context.n_of_n_taproot_public_key);

        let _input0 = connector_b.generate_taproot_leaf_tx_in(2, &input0);

        let total_output_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        // Output[0]: value=V*2%*95% to burn
        let _output0 = TxOut {
            value: total_output_amount * 95 / 100,
            script_pubkey: generate_burn_script_address(context.network).script_pubkey(),
        };

        let reward_output_amount = total_output_amount - (total_output_amount * 95 / 100);
        let _output1 = TxOut {
            value: reward_output_amount,
            script_pubkey: ScriptBuf::default(),
        };

        BurnTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf_script(2)],
            connector_b,
            reward_output_amount,
        }
    }

    fn sign_input0(&mut self, context: &VerifierContext) {
        pre_sign_taproot_input(
            self,
            context,
            0,
            TapSighashType::Single,
            self.connector_b.generate_taproot_spend_info(),
            &vec![&context.n_of_n_keypair],
        );
    }

    pub fn pre_sign(&mut self, context: &VerifierContext) { self.sign_input0(context); }

    pub fn add_output(&mut self, output_script_pubkey: ScriptBuf) {
        let output_index = 1;
        self.tx.output[output_index].script_pubkey = output_script_pubkey;
    }
}

impl BaseTransaction for BurnTransaction {
    fn finalize(&self) -> Transaction {
        if self.tx.output.len() < 2 {
            panic!("Missing output. Call add_output before finalizing");
        }

        self.tx.clone()
    }
}
