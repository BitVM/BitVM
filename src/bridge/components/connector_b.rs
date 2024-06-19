use crate::treepp::*;
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, XOnlyPublicKey,
};

use super::helper::*;

pub struct ConnectorB {
    pub n_of_n_public_key: XOnlyPublicKey,
    pub num_blocks_timelock: u32,
}

impl ConnectorB {
    pub fn new(n_of_n_public_key: &XOnlyPublicKey, num_blocks_timelock: u32) -> Self {
        ConnectorB {
            n_of_n_public_key: n_of_n_public_key.clone(),
            num_blocks_timelock
        }
    }

    // Leaf[0]: spendable by multisig of OPK and VPK[1…N]
    pub fn generate_taproot_leaf0(&self) -> Script {
        generate_pay_to_pubkey_taproot_script(&self.n_of_n_public_key)
    }

    // Leaf[1]: spendable by multisig of OPK and VPK[1…N] plus providing witness to the lock script of Assert
    pub fn generate_taproot_leaf1(&self) -> Script {
        script! {
        // TODO commit to intermediate values
        { self.n_of_n_public_key }
        OP_CHECKSIG
        }
    }

    // Leaf[2]: spendable by Burn after a TimeLock of 4 weeks plus multisig of OPK and VPK[1…N]
    pub fn generate_taproot_leaf2(
        &self
    ) -> Script {
        script! {
        { self.num_blocks_timelock }
        OP_CSV
        OP_DROP
        { self.n_of_n_public_key }
        OP_CHECKSIG
        }
    }

    // Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
    pub fn generate_taproot_spend_info(
        &self
    ) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(2, self.generate_taproot_leaf0())
            .expect("Unable to add leaf0")
            .add_leaf(2, self.generate_taproot_leaf1())
            .expect("Unable to add leaf1")
            .add_leaf(
                1,
                self.generate_taproot_leaf2(),
            )
            .expect("Unable to add leaf2")
            .finalize(&Secp256k1::new(), self.n_of_n_public_key.clone())
            .expect("Unable to finalize taproot")
    }

    pub fn generate_taproot_address(
        &self
    ) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            Network::Testnet,
        )
    }
}