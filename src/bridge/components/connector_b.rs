use crate::treepp::*;
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, Sequence, TxIn, XOnlyPublicKey,
};

use super::connector::*;
use super::helper::*;

pub struct ConnectorB {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub num_blocks_timelock: u32,
}

impl ConnectorB {
    pub fn new(network: Network, n_of_n_taproot_public_key: &XOnlyPublicKey) -> Self {
        ConnectorB {
            network,
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),
            num_blocks_timelock: if network == Network::Bitcoin {
                NUM_BLOCKS_PER_WEEK * 4
            } else {
                1
            },
        }
    }

    // Leaf[0]: spendable by multisig of OPK and VPK[1…N]
    pub fn generate_taproot_leaf0(&self) -> Script {
        generate_pay_to_pubkey_taproot_script(&self.n_of_n_taproot_public_key)
    }

    pub fn generate_taproot_leaf0_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    // Leaf[1]: spendable by multisig of OPK and VPK[1…N] plus providing witness to the lock script of Assert
    pub fn generate_taproot_leaf1(&self) -> Script {
        script! {
            // TODO commit to intermediate values
            { self.n_of_n_taproot_public_key }
            OP_CHECKSIG
        }
    }

    pub fn generate_taproot_leaf1_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    // Leaf[2]: spendable by Burn after a TimeLock of 4 weeks plus multisig of OPK and VPK[1…N]
    pub fn generate_taproot_leaf2(&self) -> Script {
        script! {
            { self.num_blocks_timelock }
            OP_CSV
            OP_DROP
            { self.n_of_n_taproot_public_key }
            OP_CHECKSIG
        }
    }

    pub fn generate_taproot_leaf2_tx_in(&self, input: &Input) -> TxIn {
        let mut tx_in = generate_default_tx_in(input);
        tx_in.sequence = Sequence(self.num_blocks_timelock & 0xFFFFFFFF);
        tx_in
    }

    // Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
    pub fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(2, self.generate_taproot_leaf0())
            .expect("Unable to add leaf0")
            .add_leaf(2, self.generate_taproot_leaf1())
            .expect("Unable to add leaf1")
            .add_leaf(1, self.generate_taproot_leaf2())
            .expect("Unable to add leaf2")
            .finalize(&Secp256k1::new(), self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    pub fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
