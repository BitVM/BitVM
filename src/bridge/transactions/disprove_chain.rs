use bitcoin::{
    absolute, consensus, Amount, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    super::{
        connectors::{base::*, connector_b::ConnectorB},
        contexts::{base::BaseContext, operator::OperatorContext, verifier::VerifierContext},
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DisproveChainTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    reward_output_amount: Amount,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for DisproveChainTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PreSignedMusig2Transaction for DisproveChainTransaction {
    fn musig2_nonces(&self) -> &HashMap<usize, HashMap<PublicKey, PubNonce>> { &self.musig2_nonces }
    fn musig2_nonces_mut(&mut self) -> &mut HashMap<usize, HashMap<PublicKey, PubNonce>> {
        &mut self.musig2_nonces
    }
    fn musig2_nonce_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, Signature>> {
        &self.musig2_nonce_signatures
    }
    fn musig2_nonce_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, Signature>> {
        &mut self.musig2_nonce_signatures
    }
    fn musig2_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &self.musig2_signatures
    }
    fn musig2_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &mut self.musig2_signatures
    }
    fn verifier_inputs(&self) -> Vec<usize> { vec![0] }
}

impl DisproveChainTransaction {
    pub fn new(context: &OperatorContext, connector_b: &ConnectorB, input_0: Input) -> Self {
        Self::new_for_validation(context.network, connector_b, input_0)
    }

    pub fn new_for_validation(network: Network, connector_b: &ConnectorB, input_0: Input) -> Self {
        let input_0_leaf = 2;
        let _input_0 = connector_b.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount / 2,
            script_pubkey: generate_burn_script_address(network).script_pubkey(),
        };

        let reward_output_amount = total_output_amount - (total_output_amount / 2);
        let _output_1 = TxOut {
            value: reward_output_amount,
            script_pubkey: ScriptBuf::default(),
        };

        DisproveChainTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0, _output_1],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf_script(input_0_leaf)],
            reward_output_amount,
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    fn sign_input_0(
        &mut self,
        context: &VerifierContext,
        connector_b: &ConnectorB,
        secret_nonce: &SecNonce,
    ) {
        let input_index = 0;
        pre_sign_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::Single,
            secret_nonce,
        );

        // TODO: Consider verifying the final signature against the n-of-n public key and the tx.
        if self.musig2_signatures[&input_index].len() == context.n_of_n_public_keys.len() {
            self.finalize_input_0(context, connector_b);
        }
    }

    fn finalize_input_0(&mut self, context: &dyn BaseContext, connector_b: &ConnectorB) {
        let input_index = 0;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::Single,
            connector_b.generate_taproot_spend_info(),
        );
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        connector_b: &ConnectorB,
        secret_nonces: &HashMap<usize, SecNonce>,
    ) {
        let input_index = 0;
        self.sign_input_0(context, connector_b, &secret_nonces[&input_index]);
    }

    pub fn add_output(&mut self, output_script_pubkey: ScriptBuf) {
        let output_index = 1;
        self.tx.output[output_index].script_pubkey = output_script_pubkey;
    }

    pub fn merge(&mut self, disprove: &DisproveChainTransaction) {
        merge_transactions(&mut self.tx, &disprove.tx);
        merge_musig2_nonces_and_signatures(self, disprove);
    }
}

impl BaseTransaction for DisproveChainTransaction {
    fn finalize(&self) -> Transaction {
        if self.tx.output.len() < 2 {
            panic!("Missing output. Call add_output before finalizing");
        }

        self.tx.clone()
    }
}
