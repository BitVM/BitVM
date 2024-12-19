use bitcoin::{Address, Network, PublicKey, ScriptBuf, TxIn};
use serde::{Deserialize, Serialize};

use crate::{
    constants::NUM_BLOCKS_PER_2_WEEKS,
    utils::num_blocks_per_network,
    scripts::*,
    transactions::base::Input,
    connectors::base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Connector4 {
    pub network: Network,
    pub operator_public_key: PublicKey,
    pub num_blocks_timelock: u32,
}

impl Connector4 {
    pub fn new(network: Network, operator_public_key: &PublicKey) -> Self {
        Connector4 {
            network,
            operator_public_key: *operator_public_key,
            num_blocks_timelock: num_blocks_per_network(network, NUM_BLOCKS_PER_2_WEEKS),
        }
    }
}

impl P2wshConnector for Connector4 {
    fn generate_script(&self) -> ScriptBuf {
        generate_timelock_script(&self.operator_public_key, self.num_blocks_timelock)
    }

    fn generate_address(&self) -> Address {
        generate_timelock_script_address(
            self.network,
            &self.operator_public_key,
            self.num_blocks_timelock,
        )
    }

    fn generate_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.num_blocks_timelock)
    }
}
