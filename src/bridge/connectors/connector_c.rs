use crate::treepp::script;
use bitcoin::{
    hashes::{ripemd160, Hash},
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use super::{super::transactions::base::Input, base::*};

// Specialized for assert leaves currently.
pub type LockScript = fn(index: u32) -> ScriptBuf;
pub type UnlockWitnessData = Vec<u8>;
pub type UnlockWitness = fn(index: u32) -> UnlockWitnessData;

pub struct DisproveLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorC {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    lock_scripts: Vec<ScriptBuf>,
    unlock_witnesses: Vec<UnlockWitnessData>,
}

impl ConnectorC {
    pub fn new(network: Network, operator_taproot_public_key: &XOnlyPublicKey) -> Self {
        let leaves = generate_assert_leaves();

        ConnectorC {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            lock_scripts: leaves.0,
            unlock_witnesses: leaves.1,
        }
    }

    pub fn generate_taproot_leaf_script_witness(&self, leaf_index: u32) -> UnlockWitnessData {
        let index = leaf_index.to_usize().unwrap();
        if index >= self.unlock_witnesses.len() {
            panic!("Invalid leaf index.")
        }
        self.unlock_witnesses[index].clone()
    }
}

impl TaprootConnector for ConnectorC {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        let index = leaf_index.to_usize().unwrap();
        if index >= self.lock_scripts.len() {
            panic!("Invalid leaf index.")
        }
        self.lock_scripts[index].clone()
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        let index = leaf_index.to_usize().unwrap();
        if index >= self.lock_scripts.len() {
            panic!("Invalid leaf index.")
        }
        generate_default_tx_in(input)
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        let script_weights = self.lock_scripts.iter().map(|script| (1, script.clone()));

        TaprootBuilder::with_huffman_tree(script_weights)
            .expect("Unable to add assert leaves")
            .finalize(&Secp256k1::new(), self.operator_taproot_public_key)
            .expect("Unable to finalize assert transaction connector c taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}

// Leaf[i] for some i in 1,2,…1000: spendable by multisig of OPK and VPK[1…N] plus the condition that f_{i}(z_{i-1})!=z_i
fn disprove_leaf() -> DisproveLeaf {
    DisproveLeaf {
        lock: |index| {
            script! {
                OP_RIPEMD160
                { ripemd160::Hash::hash(format!("SECRET_{}", index).as_bytes()).as_byte_array().to_vec() }
                OP_EQUALVERIFY
                { index }
                OP_DROP
                OP_TRUE
            }.compile()
        },
        unlock: |index| format!("SECRET_{}", index).as_bytes().to_vec(),
    }
}

fn generate_assert_leaves() -> (Vec<ScriptBuf>, Vec<UnlockWitnessData>) {
    // TODO: Scripts with n_of_n_public_key and one of the commitments disprove leaves in each leaf (Winternitz signatures)
    let mut locks = Vec::with_capacity(1000);
    let mut unlocks = Vec::with_capacity(1000);
    let locking_template = disprove_leaf().lock;
    let unlocking_template = disprove_leaf().unlock;
    for i in 0..1000 {
        locks.push(locking_template(i));
        unlocks.push(unlocking_template(i));
    }
    (locks, unlocks)
}
