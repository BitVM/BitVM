use std::collections::HashMap;

use crate::{
    bridge::{
        constants::{
            DESTINATION_NETWORK_TXID_LENGTH_IN_DIGITS, SOURCE_NETWORK_TXID_LENGTH_IN_DIGITS,
        },
        graphs::peg_out::CommitmentMessageId,
        transactions::{
            base::Input,
            signing_winternitz::{WinternitzPublicKey, WinternitzSecret},
        },
    },
    signatures::{
        winternitz::PublicKey,
        winternitz_hash::{check_hash_sig, sign_hash},
    },
    treepp::script,
};
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};

use serde::{Deserialize, Serialize};

use super::base::{generate_default_tx_in, CommitmentConnector, TaprootConnector};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Connector6 {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub commitment_public_keys: HashMap<CommitmentMessageId, WinternitzPublicKey>,
}

impl Connector6 {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
    ) -> Self {
        Connector6 {
            network,
            operator_taproot_public_key: operator_taproot_public_key.clone(),
            commitment_public_keys: commitment_public_keys.clone(),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let destination_network_txid_public_key = PublicKey::from(
            &self.commitment_public_keys[&CommitmentMessageId::PegOutTxIdDestinationNetwork],
        );
        let source_network_txid_public_key = PublicKey::from(
            &self.commitment_public_keys[&CommitmentMessageId::PegOutTxIdSourceNetwork],
        );

        script! {
          { check_hash_sig(&destination_network_txid_public_key, DESTINATION_NETWORK_TXID_LENGTH_IN_DIGITS) }
          { check_hash_sig(&source_network_txid_public_key, SOURCE_NETWORK_TXID_LENGTH_IN_DIGITS) }
          { self.operator_taproot_public_key }
          OP_CHECKSIG
        }
        .compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }

    pub fn generate_taproot_leaf_0_witness(
        &self,
        commitment_secret: &WinternitzSecret,
        message_digits: &[u8],
    ) -> Vec<Vec<u8>> {
        let mut unlock_data: Vec<Vec<u8>> = Vec::new();

        // Push the message
        for byte in message_digits.iter().rev() {
            unlock_data.push(vec![*byte]);
        }

        // Push the signature
        let winternitz_signatures = sign_hash(commitment_secret.into(), &message_digits);
        for winternitz_signature in winternitz_signatures.into_iter() {
            unlock_data.push(winternitz_signature.hash_bytes);
            unlock_data.push(vec![winternitz_signature.message_digit]);
        }

        unlock_data
    }
}

impl TaprootConnector for Connector6 {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .finalize(&Secp256k1::new(), self.operator_taproot_public_key) // TODO: should be operator key?
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}

impl CommitmentConnector for Connector6 {
    fn generate_commitment_witness(
        &self,
        leaf_index: u32,
        commitment_secret: &WinternitzSecret,
        message: &[u8],
    ) -> Vec<Vec<u8>> {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_witness(commitment_secret, message),
            _ => panic!("Invalid leaf index."),
        }
    }
}
