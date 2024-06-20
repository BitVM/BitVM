use crate::treepp::*;
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, Sequence, TxIn, XOnlyPublicKey,
};

use super::connector::*;
use super::helper::*;

pub struct ConnectorZ {
    pub network: Network,
    pub depositor_taproot_public_key: XOnlyPublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub evm_address: String,
}

impl ConnectorZ {
    pub fn new(
        network: Network,
        evm_address: &str,
        depositor_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) -> Self {
        ConnectorZ {
            network,
            depositor_taproot_public_key: depositor_taproot_public_key.clone(),
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),
            evm_address: evm_address.to_string(),
        }
    }

    // leaf[0] is TimeLock script that the depositor can spend after timelock, if leaf[1] has not been spent
    pub fn generate_taproot_leaf0(&self) -> Script {
        script! {
        { NUM_BLOCKS_PER_WEEK * 2 }
        OP_CSV
        OP_DROP
        { self.depositor_taproot_public_key }
        OP_CHECKSIG
        }
    }

    pub fn generate_taproot_leaf0_tx_in(&self, input: &Input) -> TxIn {
        let mut tx_in = generate_default_tx_in(input);
        tx_in.sequence = Sequence(NUM_BLOCKS_PER_WEEK * 2);
        tx_in
    }

    // leaf[1] is spendable by a multisig of depositor and OPK and VPK[1…N]
    // the transaction script contains an [evm_address] (inscription data)
    pub fn generate_taproot_leaf1(&self) -> Script {
        script! {
        OP_FALSE
        OP_IF
        { String::from("ord").into_bytes() } // TODO Decide if this metadata is needed or not
        1
        { String::from("text/plain;charset=utf-8").into_bytes() } // TODO change to json for clearer meaning
        0
        { self.evm_address.clone().into_bytes() }
        OP_ENDIF
        { self.n_of_n_taproot_public_key }
        OP_CHECKSIGVERIFY
        { self.depositor_taproot_public_key }
        OP_CHECKSIG
        }
    }

    pub fn generate_taproot_leaf1_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }

    pub fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.generate_taproot_leaf0())
            .expect("Unable to add leaf0")
            .add_leaf(1, self.generate_taproot_leaf1())
            .expect("Unable to add leaf1")
            .finalize(&Secp256k1::new(), self.depositor_taproot_public_key) // TODO: should this be depositor or n-of-n
            .expect("Unable to finalize ttaproot")
    }

    pub fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
