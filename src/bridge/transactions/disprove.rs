use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, Transaction,
    TxOut, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{connector::*, connector_3::Connector3, connector_c::ConnectorC},
        contexts::{operator::OperatorContext, verifier::VerifierContext},
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
    signing::push_taproot_leaf_script_and_control_block_to_witness,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DisproveTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_c: ConnectorC,
    reward_output_amount: Amount,
}

impl PreSignedTransaction for DisproveTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl DisproveTransaction {
    pub fn new(context: &OperatorContext, input0: Input, input1: Input, script_index: u32) -> Self {
        Self::new_for_validation(
            context.network,
            &context.n_of_n_public_key,
            &context.n_of_n_taproot_public_key,
            input0,
            input1,
            script_index,
        )
    }

    pub fn new_for_validation(
        network: Network,
        n_of_n_public_key: &PublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        input0: Input,
        input1: Input,
        script_index: u32,
    ) -> Self {
        let connector_3 = Connector3::new(network, &n_of_n_public_key);
        let connector_c = ConnectorC::new(network, &n_of_n_taproot_public_key);

        let _input0 = connector_3.generate_tx_in(&input0);

        let _input1 = connector_c.generate_taproot_leaf_tx_in(script_index, &input1);

        let total_output_amount = input0.amount + input1.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_output_amount / 2,
            script_pubkey: generate_burn_script_address(network).script_pubkey(),
        };

        let reward_output_amount = total_output_amount - (total_output_amount / 2);
        let _output1 = TxOut {
            value: reward_output_amount,
            script_pubkey: ScriptBuf::default(),
        };

        DisproveTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1],
                output: vec![_output0, _output1],
            },
            prev_outs: vec![
                TxOut {
                    value: input0.amount,
                    script_pubkey: connector_3.generate_address().script_pubkey(),
                },
                TxOut {
                    value: input1.amount,
                    script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![connector_3.generate_script()],
            connector_c,
            reward_output_amount,
        }
    }

    fn sign_input0(&mut self, context: &VerifierContext) {
        pre_sign_p2wsh_input(
            self,
            context,
            0,
            EcdsaSighashType::Single,
            &vec![&context.n_of_n_keypair],
        );
    }

    pub fn pre_sign(&mut self, context: &VerifierContext) { self.sign_input0(context); }

    pub fn add_input_output(&mut self, input_script_index: u32, output_script_pubkey: ScriptBuf) {
        // Add output
        let output_index = 1;
        self.tx.output[output_index].script_pubkey = output_script_pubkey;

        let input_index = 1;

        // TODO: Doesn't this needs to be signed sighash_single or sighash_all? Shouln't leave these input/outputs unsigned

        // Push the unlocking witness
        let unlock_witness = self
            .connector_c
            .generate_taproot_leaf_script_witness(input_script_index);
        self.tx.input[input_index].witness.push(unlock_witness);

        // Push script + control block
        let script = self
            .connector_c
            .generate_taproot_leaf_script(input_script_index);
        let taproot_spend_info = self.connector_c.generate_taproot_spend_info();
        push_taproot_leaf_script_and_control_block_to_witness(
            &mut self.tx,
            input_index,
            &taproot_spend_info,
            &script,
        );
    }

    pub fn merge(&mut self, disprove: &DisproveTransaction) {
        merge_transactions(&mut self.tx, &disprove.tx);
    }
}

impl BaseTransaction for DisproveTransaction {
    fn finalize(&self) -> Transaction {
        if self.tx.input.len() < 2 || self.tx.output.len() < 2 {
            panic!("Missing input or output. Call add_input_output before finalizing");
        }

        self.tx.clone()
    }
}
