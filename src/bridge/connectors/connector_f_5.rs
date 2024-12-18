use bitcoin::{Address, Network, PublicKey, ScriptBuf, TxIn};
use serde::{Deserialize, Serialize};

use super::{
    super::{scripts::*, transactions::base::Input},
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorF5 {
    pub network: Network,
    pub operator_public_key: PublicKey,
}

impl ConnectorF5 {
    pub fn new(network: Network, operator_public_key: &PublicKey) -> Self {
        ConnectorF5 {
            network,
            operator_public_key: *operator_public_key,
        }
    }
}

impl P2wshConnector for ConnectorF5 {
    fn generate_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_script(&self.operator_public_key)
    }

    fn generate_address(&self) -> Address {
        Address::p2wsh(
            &generate_pay_to_pubkey_script(&self.operator_public_key),
            self.network,
        )
    }

    fn generate_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }
}
