use bitcoin::{absolute, consensus, Amount, ScriptBuf, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use bitvm::{chunker::common::RawWitness, execute_raw_script_with_inputs};

use crate::transactions::signing::populate_taproot_input_witness;

use super::{
    super::{
        super::connectors::{base::*, connector_f_2::ConnectorF2},
        base::*,
        pre_signed::*,
    },
    utils::AssertCommit2ConnectorsE,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertCommit2Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for AssertCommit2Transaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl AssertCommit2Transaction {
    pub fn new(
        connectors_e: &AssertCommit2ConnectorsE,
        connector_f_2: &ConnectorF2,
        tx_inputs: Vec<Input>,
    ) -> Self {
        assert_eq!(
            tx_inputs.len(),
            connectors_e.connectors_num(),
            "inputs and connectors e don't match"
        );

        Self::new_for_validation(connectors_e, connector_f_2, tx_inputs)
    }

    pub fn new_for_validation(
        connectors_e: &AssertCommit2ConnectorsE,
        connector_f_2: &ConnectorF2,
        tx_inputs: Vec<Input>,
    ) -> Self {
        let mut inputs = vec![];
        let mut prev_outs = vec![];
        let mut prev_scripts = vec![];
        let mut total_output_amount = Amount::from_sat(0);

        for (connector_e, input) in (0..connectors_e.connectors_num())
            .map(|idx| connectors_e.get_connector_e(idx))
            .zip(tx_inputs)
        {
            inputs.push(connector_e.generate_taproot_leaf_tx_in(0, &input));
            prev_outs.push(TxOut {
                value: input.amount,
                script_pubkey: connector_e.generate_taproot_address().script_pubkey(),
            });
            prev_scripts.push(connector_e.generate_taproot_leaf_script(0));
            total_output_amount += input.amount;
        }
        total_output_amount -= Amount::from_sat(MIN_RELAY_FEE_ASSERT_COMMIT2);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_f_2.generate_address().script_pubkey(),
        };

        AssertCommit2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: inputs,
                output: vec![_output_0],
            },
            prev_outs,
            prev_scripts,
        }
    }

    pub fn sign(&mut self, connectors_e: &AssertCommit2ConnectorsE, witnesses: Vec<RawWitness>) {
        assert_eq!(witnesses.len(), connectors_e.connectors_num());
        for (input_index, witness) in (0..connectors_e.connectors_num()).zip(witnesses) {
            let taproot_spend_info = connectors_e
                .get_connector_e(input_index)
                .generate_taproot_spend_info();
            let script = &self.prev_scripts()[input_index].clone();
            let res = execute_raw_script_with_inputs(script.clone().to_bytes(), witness.clone());
            assert!(
                res.success,
                "script: {:?}, res: {:?}: stack: {:?}, variable name: {:?}",
                script,
                res,
                res.final_stack,
                connectors_e
                    .get_connector_e(input_index)
                    .commitment_public_keys
                    .keys()
            );
            populate_taproot_input_witness(
                self.tx_mut(),
                input_index,
                &taproot_spend_info,
                script,
                witness,
            );
        }
    }

    pub fn merge(&mut self, assert_commit_2: &AssertCommit2Transaction) {
        merge_transactions(&mut self.tx, &assert_commit_2.tx);
    }
}

impl BaseTransaction for AssertCommit2Transaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
    fn name(&self) -> &'static str { "AssertCommit2" }
}
