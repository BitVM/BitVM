use std::collections::BTreeMap;

use crate::{
    bridge::{
        common::ZkProofVerifyingKey, error::Error, graphs::peg_out::CommitmentMessageId,
        transactions::signing_winternitz::WinternitzPublicKey,
        utils::remove_script_and_control_block_from_witness,
    },
    chunker::{
        assigner::BridgeAssigner,
        chunk_groth16_verifier::groth16_verify_to_segments,
        common::RawWitness,
        disprove_execution::{disprove_exec, RawProof},
    },
};
use bitcoin::{
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, Transaction, TxIn, XOnlyPublicKey,
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

pub type LockScriptsGenerator =
    fn(&BTreeMap<CommitmentMessageId, WinternitzPublicKey>) -> Vec<ScriptBuf>;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorC {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub lock_scripts: Vec<ScriptBuf>,
    commitment_public_keys: BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
}

impl ConnectorC {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
        lock_scripts_generator: LockScriptsGenerator,
        lock_scripts_cache: Option<Vec<ScriptBuf>>,
    ) -> Self {
        ConnectorC {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            lock_scripts: match lock_scripts_cache {
                Some(lock_scripts) => lock_scripts,
                None => lock_scripts_generator(commitment_public_keys),
            },
            commitment_public_keys: commitment_public_keys.clone(),
        }
    }

    pub fn generate_disprove_witness(
        &self,
        commit_1_witness: Vec<RawWitness>,
        commit_2_witness: Vec<RawWitness>,
        vk: &ZkProofVerifyingKey,
    ) -> Result<(usize, RawWitness), Error> {
        let pks = self
            .commitment_public_keys
            .clone()
            .into_iter()
            .map(|(k, v)| {
                (
                    match k {
                        CommitmentMessageId::Groth16IntermediateValues((name, _)) => name,
                        _ => String::new(),
                    },
                    v,
                )
            })
            .collect();
        let mut assigner = BridgeAssigner::new_watcher(pks);
        // merge commit1 and commit2
        disprove_exec(
            &mut assigner,
            vec![commit_1_witness, commit_2_witness],
            vk.clone(),
        )
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

pub fn generate_assert_leaves(
    commits_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
) -> Vec<ScriptBuf> {
    // hash map to btree map
    let pks = commits_public_keys
        .clone()
        .into_iter()
        .map(|(k, v)| {
            (
                match k {
                    CommitmentMessageId::Groth16IntermediateValues((name, _)) => name,
                    _ => String::new(),
                },
                v,
            )
        })
        .collect();
    let mut bridge_assigner = BridgeAssigner::new_watcher(pks);
    let default_proof = RawProof::default(); // mock a default proof to generate scripts

    let segments = groth16_verify_to_segments(
        &mut bridge_assigner,
        &default_proof.public,
        &default_proof.proof,
        &default_proof.vk,
    );

    let mut locks = Vec::with_capacity(1000);
    for segment in segments {
        locks.push(segment.script(&bridge_assigner).compile());
    }
    locks
}

pub fn get_commit_from_assert_commit_tx(assert_commit_tx: &Transaction) -> Vec<RawWitness> {
    let mut assert_commit_witness = Vec::new();
    for input in assert_commit_tx.input.iter() {
        // remove script and control block from witness
        let witness = remove_script_and_control_block_from_witness(input.witness.to_vec());
        assert_commit_witness.push(witness);
    }

    assert_commit_witness
}
