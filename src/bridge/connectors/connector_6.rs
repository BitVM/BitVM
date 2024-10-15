use std::collections::HashMap;

use crate::{
    bridge::{
        constants::{BITCOIN_TXID_LENGTH_IN_DIGITS, ETHEREUM_TXID_LENGTH_IN_DIGITS},
        transactions::{
            base::Input,
            signing_winternitz::{
                convert_winternitz_public_key, generate_winternitz_secret,
                winternitz_public_key_from_secret, WinternitzPublicKey, WinternitzSecret,
            },
        },
    },
    signatures::winternitz_hash::{check_hash_sig, sign_hash},
    treepp::script,
};
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};

use serde::{Deserialize, Serialize};

use super::base::{
    generate_default_tx_in, BaseConnector, CommitmentConnector, ConnectorId, TaprootConnector,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Connector6 {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub winternitz_public_keys: HashMap<u8, WinternitzPublicKey>, // Leaf index -> WinternitzPublicKey
}

impl Connector6 {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
    ) -> (Self, HashMap<u8, WinternitzSecret>) {
        let leaf_index = 0;
        let winternitz_secrets = HashMap::from([(leaf_index, generate_winternitz_secret())]);
        let winternitz_public_keys = winternitz_secrets
            .iter()
            .map(|(k, v)| (*k, winternitz_public_key_from_secret(&v)))
            .collect();

        let this = Self::new_for_validation(
            network,
            operator_taproot_public_key,
            &winternitz_public_keys,
        );

        (this, winternitz_secrets)
    }

    pub fn new_for_validation(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        winternitz_public_keys: &HashMap<u8, WinternitzPublicKey>,
    ) -> Self {
        Connector6 {
            network,
            operator_taproot_public_key: operator_taproot_public_key.clone(),
            winternitz_public_keys: winternitz_public_keys.clone(),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let leaf_index = 0;
        let winternitz_public_key =
            convert_winternitz_public_key(&self.winternitz_public_keys[&leaf_index]);

        script! {
          { check_hash_sig(&winternitz_public_key, ETHEREUM_TXID_LENGTH_IN_DIGITS) }
          { check_hash_sig(&winternitz_public_key, BITCOIN_TXID_LENGTH_IN_DIGITS) }
          { self.operator_taproot_public_key }
          OP_CHECKSIG
        }
        .compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }

    pub fn generate_taproot_leaf_0_witness(
        &self,
        winternitz_secret: &WinternitzSecret,
        message: &[u8],
    ) -> Vec<Vec<u8>> {
        let mut unlock_data: Vec<Vec<u8>> = Vec::new();

        // Push the message
        for byte in message.iter().rev() {
            unlock_data.push(vec![*byte]);
        }

        // Push the signature
        let witnernitz_signatures = sign_hash(winternitz_secret, &message);
        for winternitz_signature in witnernitz_signatures.into_iter() {
            unlock_data.push(winternitz_signature.hash_bytes);
            unlock_data.push(vec![winternitz_signature.message_digit]);
        }

        unlock_data
    }
}

impl BaseConnector for Connector6 {
    fn id(&self) -> ConnectorId { ConnectorId::Connector6 }
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
        winternitz_secret: &WinternitzSecret,
        message: &[u8],
    ) -> Vec<Vec<u8>> {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_witness(winternitz_secret, message),
            _ => panic!("Invalid leaf index."),
        }
    }
}
