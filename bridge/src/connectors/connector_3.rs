use bitcoin::{Address, Network, PublicKey, ScriptBuf, TxIn};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        scripts::*,
        transactions::base::Input,
        {constants::NUM_BLOCKS_PER_3_DAYS, utils::num_blocks_per_network},
    },
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Connector3 {
    pub network: Network,
    pub operator_public_key: PublicKey,
    pub num_blocks_timelock: u32,
}

impl Connector3 {
    pub fn new(network: Network, operator_public_key: &PublicKey) -> Self {
        Connector3 {
            network,
            operator_public_key: *operator_public_key,
            num_blocks_timelock: num_blocks_per_network(network, NUM_BLOCKS_PER_3_DAYS),
        }
    }
}

impl P2wshConnector for Connector3 {
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
