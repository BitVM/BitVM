use crate::treepp::*;
use bitcoin::{
    hashes::{ripemd160, Hash},
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, TxIn, XOnlyPublicKey,
};
use num_traits::ToPrimitive;

use super::{super::transactions::bridge::Input, connector::*};

// Specialized for assert leaves currently.
pub type LockScript = fn(index: u32) -> Script;
pub type UnlockWitnessData = Vec<Vec<u8>>;
pub type UnlockWitness = fn(index: u32) -> UnlockWitnessData;

pub struct AssertLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

pub struct ConnectorC {
    pub network: Network,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    lock_scripts: Vec<Script>,
    unlock_witnesses: Vec<UnlockWitnessData>,
}

impl ConnectorC {
    pub fn new(network: Network, n_of_n_taproot_public_key: &XOnlyPublicKey) -> Self {
        let leaves = generate_assert_leaves();

        ConnectorC {
            network,
            n_of_n_taproot_public_key: n_of_n_taproot_public_key.clone(),
            lock_scripts: leaves.0,
            unlock_witnesses: leaves.1,
        }
    }

    pub fn generate_taproot_leaf_script_witness(&self, leaf_index: u32) -> UnlockWitnessData {
        let index = leaf_index.to_usize().unwrap();
        if (index >= self.unlock_witnesses.len()) {
            panic!("Invalid leaf index.")
        }
        self.unlock_witnesses[index].clone()
    }
}

impl TaprootConnector for ConnectorC {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> Script {
        let index = leaf_index.to_usize().unwrap();
        if (index >= self.lock_scripts.len()) {
            panic!("Invalid leaf index.")
        }
        self.lock_scripts[index].clone()
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        let index = leaf_index.to_usize().unwrap();
        if (index >= self.lock_scripts.len()) {
            panic!("Invalid leaf index.")
        }
        generate_default_tx_in(input)
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        let script_weights = self.lock_scripts.iter().map(|script| (1, script.clone()));

        TaprootBuilder::with_huffman_tree(script_weights)
            .expect("Unable to add assert leaves")
            // Finalizing with n_of_n_public_key allows the key-path spend with the
            // n_of_n
            .finalize(&Secp256k1::new(), self.n_of_n_taproot_public_key)
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
fn assert_leaf() -> AssertLeaf {
    AssertLeaf {
        lock: |index| {
            script! {
                OP_RIPEMD160
                { ripemd160::Hash::hash(format!("SECRET_{}", index).as_bytes()).as_byte_array().to_vec() }
                OP_EQUALVERIFY
                { index }
                OP_DROP
                OP_TRUE
            }
        },
        unlock: |index| vec![format!("SECRET_{}", index).as_bytes().to_vec()],
    }
}

fn generate_assert_leaves() -> (Vec<Script>, Vec<UnlockWitnessData>) {
    // TODO: Scripts with n_of_n_public_key and one of the commitments disprove leaves in each leaf (Winternitz signatures)
    let mut locks = Vec::with_capacity(1000);
    let mut unlocks = Vec::with_capacity(1000);
    let locking_template = assert_leaf().lock;
    let unlocking_template = assert_leaf().unlock;
    for i in 0..1000 {
        locks.push(locking_template(i));
        unlocks.push(unlocking_template(i));
    }
    (locks, unlocks)
}
