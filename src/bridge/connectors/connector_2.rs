use std::collections::HashMap;

use crate::{
    bridge::{
        constants::N_SEQUENCE_FOR_LOCK_TIME, graphs::peg_out::CommitmentMessageId,
        transactions::signing_winternitz::WinternitzPublicKeyVariant,
    },
    signatures::winternitz_compact::{PublicKeyCompact, N_32},
    treepp::script,
};
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        super::signatures::winternitz_compact::{checksig_verify, digits_to_number, N0_32},
        scripts::*,
        transactions::base::Input,
    },
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Connector2 {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub commitment_public_keys: HashMap<CommitmentMessageId, WinternitzPublicKeyVariant>,
}

impl Connector2 {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKeyVariant>,
    ) -> Self {
        Connector2 {
            network,
            operator_taproot_public_key: operator_taproot_public_key.clone(),
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),
            commitment_public_keys: commitment_public_keys.clone(),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let start_time_public_key = self.commitment_public_keys[&CommitmentMessageId::StartTime]
            .get_compact_n32_variant_ref();

        script! {
            // pre-image (pushed to stack from witness)
            // BITVM1 opcodes
            // block peg out was mined in (left on stack)
            { checksig_verify::<N_32, N0_32>(&PublicKeyCompact::from(start_time_public_key)) }
            { digits_to_number::<N0_32>() }
            OP_CLTV
            OP_DROP
            { self.operator_taproot_public_key }
            OP_CHECKSIG
        }
        .compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, N_SEQUENCE_FOR_LOCK_TIME)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        generate_pay_to_pubkey_taproot_script(&self.n_of_n_taproot_public_key)
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }
}

impl TaprootConnector for Connector2 {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(1, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .finalize(&Secp256k1::new(), self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
