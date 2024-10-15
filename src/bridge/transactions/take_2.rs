use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, TapSighashType,
    Transaction, TxOut, XOnlyPublicKey,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    super::{
        connectors::{
            base::*, connector_0::Connector0, connector_4::Connector4, connector_5::Connector5,
            connector_c::ConnectorC,
        },
        contexts::{base::BaseContext, operator::OperatorContext, verifier::VerifierContext},
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Take2Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    connector_0: Connector0,
    connector_4: Connector4,
    connector_5: Connector5,
    connector_c: ConnectorC,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for Take2Transaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PreSignedMusig2Transaction for Take2Transaction {
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
}

impl Take2Transaction {
    pub fn new(
        context: &OperatorContext,
        input_0: Input,
        input_1: Input,
        input_2: Input,
        input_3: Input,
    ) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            input_0,
            input_1,
            input_2,
            input_3,
        );

        this.sign_input_1(context);
        this.sign_input_3(context);

        this
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        input_0: Input,
        input_1: Input,
        input_2: Input,
        input_3: Input,
    ) -> Self {
        let connector_0 = Connector0::new(network, n_of_n_taproot_public_key);
        let connector_4 = Connector4::new(network, operator_public_key);
        let connector_5 = Connector5::new(network, n_of_n_taproot_public_key);
        let connector_c = ConnectorC::new(network, operator_taproot_public_key);

        let input_0_leaf = 1;
        let _input_0 = connector_0.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let _input_1 = connector_4.generate_tx_in(&input_1);

        let input_2_leaf = 0;
        let _input_2 = connector_5.generate_taproot_leaf_tx_in(input_2_leaf, &input_2);

        let input_3_leaf = 0;
        let _input_3 = connector_c.generate_taproot_leaf_tx_in(input_3_leaf, &input_3);

        let total_output_amount = input_0.amount + input_1.amount + input_2.amount + input_3.amount
            - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                .script_pubkey(),
        };

        Take2Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1, _input_2, _input_3],
                output: vec![_output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: connector_4.generate_address().script_pubkey(),
                },
                TxOut {
                    value: input_2.amount,
                    script_pubkey: connector_5.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_3.amount,
                    script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_0.generate_taproot_leaf_script(input_0_leaf),
                connector_4.generate_script(),
                connector_5.generate_taproot_leaf_script(input_2_leaf),
                connector_c.generate_taproot_leaf_script(input_3_leaf),
            ],
            connector_0,
            connector_4,
            connector_5,
            connector_c,
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    pub fn num_blocks_timelock_1(&self) -> u32 { self.connector_4.num_blocks_timelock }

    fn sign_input_0(&mut self, context: &VerifierContext, secret_nonce: &SecNonce) {
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
            self.finalize_input_0(context);
        }
    }

    fn finalize_input_0(&mut self, context: &dyn BaseContext) {
        let input_index = 0;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            self.connector_0.generate_taproot_spend_info(),
        );
    }

    fn sign_input_1(&mut self, context: &OperatorContext) {
        let input_index = 1;
        pre_sign_p2wsh_input(
            self,
            context,
            input_index,
            EcdsaSighashType::All,
            &vec![&context.operator_keypair],
        );
    }

    fn sign_input_2(&mut self, context: &VerifierContext, secret_nonce: &SecNonce) {
        let input_index = 2;
        pre_sign_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            secret_nonce,
        );

        // TODO: Consider verifying the final signature against the n-of-n public key and the tx.
        if self.musig2_signatures[&input_index].len() == context.n_of_n_public_keys.len() {
            self.finalize_input_2(context);
        }
    }

    fn finalize_input_2(&mut self, context: &dyn BaseContext) {
        let input_index = 2;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            self.connector_5.generate_taproot_spend_info(),
        );
    }

    fn sign_input_3(&mut self, context: &OperatorContext) {
        let input_index = 3;
        pre_sign_taproot_input_default(
            self,
            context,
            input_index,
            TapSighashType::All,
            self.connector_c.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    pub fn push_nonces(&mut self, context: &VerifierContext) -> HashMap<usize, SecNonce> {
        let mut secret_nonces = HashMap::new();

        let input_index = 0;
        let secret_nonce = push_nonce(self, context, input_index);
        secret_nonces.insert(input_index, secret_nonce);

        let input_index = 2;
        let secret_nonce = push_nonce(self, context, input_index);
        secret_nonces.insert(input_index, secret_nonce);

        secret_nonces
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        secret_nonces: &HashMap<usize, SecNonce>,
    ) {
        let input_index = 0;
        self.sign_input_0(context, &secret_nonces[&input_index]);

        let input_index = 2;
        self.sign_input_2(context, &secret_nonces[&input_index]);
    }

    pub fn merge(&mut self, take_2: &Take2Transaction) {
        merge_transactions(&mut self.tx, &take_2.tx);
        merge_musig2_nonces_and_signatures(self, take_2);
    }
}

impl BaseTransaction for Take2Transaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
