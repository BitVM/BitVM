use crate::treepp::*;
use bitcoin::{Address, Network, PublicKey, TxIn};

use super::connector::*;
use super::helper::*;

pub struct Connector3 {
    pub network: Network,
    pub n_of_n_public_key: PublicKey,
}

impl Connector3 {
    pub fn new(network: Network, n_of_n_public_key: &PublicKey) -> Self {
        Connector3 {
            network,
            n_of_n_public_key: n_of_n_public_key.clone(),
        }
    }

    pub fn generate_script(&self) -> Script {
        generate_pay_to_pubkey_script(&self.n_of_n_public_key)
    }

    pub fn generate_script_address(&self) -> Address {
        generate_pay_to_pubkey_script_address(self.network, &self.n_of_n_public_key)
    }

    pub fn generate_script_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}
