use crate::{
    bridge::{
        constants::{BITCOIN_TXID_LEN, ETHEREUM_TXID_LEN},
        transactions::base::Input,
    },
    signatures::{
        winternitz::generate_public_key,
        winternitz_hash::{check_hash_sig, sign_hash},
    },
    treepp::script,
};
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, Txid, XOnlyPublicKey,
};

use serde::{Deserialize, Serialize};

use super::connector::{generate_default_tx_in, TaprootConnector};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Connector6 {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub evm_txid: Option<String>,
    pub peg_out_txid: Option<Txid>,
}

impl Connector6 {
    pub fn new(network: Network, operator_taproot_public_key: &XOnlyPublicKey) -> Self {
        Connector6 {
            network,
            operator_taproot_public_key: operator_taproot_public_key.clone(),
            evm_txid: None,
            peg_out_txid: None,
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let secret_key = "b138982ce17ac813d505b5b40b665d404e9528e7"; // TODO replace with secret key for specific variable, generate and store secrets in local client
        let public_key = generate_public_key(secret_key);

        script! {
          { check_hash_sig(&public_key, ETHEREUM_TXID_LEN) }
          { check_hash_sig(&public_key, BITCOIN_TXID_LEN) }
          { self.operator_taproot_public_key }
          OP_CHECKSIG
        }
        .compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }

    pub fn generate_taproot_leaf_0_unlock(&self, txid: &str) -> Vec<Vec<u8>> {
        let secret_key = "b138982ce17ac813d505b5b40b665d404e9528e7"; // TODO replace with secret key for specific variable, generate and store secrets in local client
        let mut unlock_data: Vec<Vec<u8>> = Vec::new();
        let message = txid.as_bytes();

        // Push the message
        for byte in message.iter().rev() {
            unlock_data.push(vec![*byte]);
        }

        // Push the signature
        let witnernitz_signatures = sign_hash(secret_key, &message);
        for winternitz_signature in witnernitz_signatures.into_iter() {
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
