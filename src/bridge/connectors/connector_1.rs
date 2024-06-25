use crate::treepp::*;
use bitcoin::{Address, Network, PublicKey, Sequence, TxIn};

use super::{
    super::{scripts::*, transactions::base::Input},
    connector::*,
};

pub struct Connector1 {
    pub network: Network,
    pub operator_public_key: PublicKey,
    pub num_blocks_timelock: u32,
}

impl Connector1 {
    pub fn new(network: Network, operator_public_key: &PublicKey) -> Self {
        Connector1 {
            network,
            operator_public_key: operator_public_key.clone(),
            num_blocks_timelock: if network == Network::Bitcoin {
                NUM_BLOCKS_PER_WEEK * 2
            } else {
                1
            },
        }
    }
}

impl P2wshConnector for Connector1 {
    fn generate_script(&self) -> Script {
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
        let mut tx_in = generate_default_tx_in(input);
        tx_in.sequence = Sequence((self.num_blocks_timelock) & 0xFFFFFFFF);
        tx_in
    }
}
