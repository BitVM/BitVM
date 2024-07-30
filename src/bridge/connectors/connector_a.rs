use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{scripts::*, transactions::base::Input},
    connector::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorA {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl ConnectorA {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) -> Self {
        ConnectorA {
            network,
            operator_taproot_public_key: operator_taproot_public_key.clone(),
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),
        }
    }

    // leaf[0]: spendable by operator
    fn generate_taproot_leaf0_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.operator_taproot_public_key)
    }

    fn generate_taproot_leaf0_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }

    // leaf[1]: spendable by operator with sighash flag=“Single|AnyoneCanPay”, spendable along with any other inputs such that the output value exceeds V*1%
    fn generate_taproot_leaf1_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.operator_taproot_public_key)
    }

    fn generate_taproot_leaf1_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }
}

impl TaprootConnector for ConnectorA {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf0_script(),
            1 => self.generate_taproot_leaf1_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf0_tx_in(input),
            1 => self.generate_taproot_leaf1_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.generate_taproot_leaf0_script())
            .expect("Unable to add leaf0")
            .add_leaf(1, self.generate_taproot_leaf1_script())
            .expect("Unable to add leaf1")
            .finalize(&Secp256k1::new(), self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
