use bitcoin::{
    absolute, consensus, Amount, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    super::{
        connectors::{
            base::*, connector_4::Connector4, connector_5::Connector5, connector_b::ConnectorB,
            connector_c::ConnectorC,
        },
        contexts::{base::BaseContext, verifier::VerifierContext},
        graphs::base::DUST_AMOUNT,
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for AssertTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PreSignedMusig2Transaction for AssertTransaction {
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

impl AssertTransaction {
    pub fn new(
        connector_4: &Connector4,
        connector_5: &Connector5,
        connector_b: &ConnectorB,
        connector_c: &ConnectorC,
        input_0: Input,
    ) -> Self {
        Self::new_for_validation(connector_4, connector_5, connector_b, connector_c, input_0)
    }

    pub fn new_for_validation(
        connector_4: &Connector4,
        connector_5: &Connector5,
        connector_b: &ConnectorB,
        connector_c: &ConnectorC,
        input_0: Input,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = connector_b.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(MIN_RELAY_FEE_ASSERT);

        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_4.generate_address().script_pubkey(),
        };

        let _output_2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
        };

        let _output_1 = TxOut {
            value: total_output_amount - _output_0.value - _output_2.value,
            script_pubkey: connector_5.generate_taproot_address().script_pubkey(),
        };

        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0, _output_1, _output_2],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf_script(input_0_leaf)],
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
            TapSighashType::All,
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
            TapSighashType::All,
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

    pub fn merge(&mut self, assert: &AssertTransaction) {
        merge_transactions(&mut self.tx, &assert.tx);
        merge_musig2_nonces_and_signatures(self, assert);
    }
}

impl BaseTransaction for AssertTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
