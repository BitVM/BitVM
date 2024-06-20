use crate::treepp::*;
use bitcoin::{Address, Network, PublicKey, Sequence, TxIn};

use super::connector::*;
use super::helper::*;

pub struct Connector1 {
    pub network: Network,
    pub operator_public_key: PublicKey,
}

impl Connector1 {
    pub fn new(network: Network, operator_public_key: &PublicKey) -> Self {
        Connector1 {
            network,
            operator_public_key: operator_public_key.clone(),
        }
    }
}

impl P2wshConnector for Connector1 {
    fn generate_script(&self) -> Script { generate_timelock_script(&self.operator_public_key, 2) }

    fn generate_address(&self) -> Address {
        generate_timelock_script_address(self.network, &self.operator_public_key, 2)
    }

    fn generate_tx_in(&self, input: &Input) -> TxIn {
        let mut tx_in = generate_default_tx_in(input);
        tx_in.sequence =
            Sequence(u32::try_from(NUM_BLOCKS_PER_WEEK * 2).ok().unwrap() & 0xFFFFFFFF);
        tx_in
    }
}
