use crate::treepp::*;
use bitcoin::{Address, Network, PublicKey, Sequence, TxIn};

use super::connector::*;
use super::helper::*;

pub struct Connector2 {
    pub network: Network,
    pub n_of_n_public_key: PublicKey,
    pub num_blocks_timelock: u32,
}

impl Connector2 {
    pub fn new(network: Network, n_of_n_public_key: &PublicKey) -> Self {
        Connector2 {
            network,
            n_of_n_public_key: n_of_n_public_key.clone(),
            num_blocks_timelock: if network == Network::Bitcoin { NUM_BLOCKS_PER_WEEK * 2 } else { 1 },
        }
    }

    pub fn generate_script(&self) -> Script {
        generate_timelock_script(&self.n_of_n_public_key, self.num_blocks_timelock)
    }

    pub fn generate_script_address(&self) -> Address {
        generate_timelock_script_address(self.network, &self.n_of_n_public_key, self.num_blocks_timelock)
    }

    pub fn generate_script_tx_in(&self, input: &Input) -> TxIn {
        let mut tx_in = generate_default_tx_in(input);
        tx_in.sequence =
            Sequence(u32::try_from(NUM_BLOCKS_PER_WEEK * 2).ok().unwrap() & 0xFFFFFFFF);
        tx_in
    }
}
