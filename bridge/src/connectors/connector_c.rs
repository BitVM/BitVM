use std::{
    collections::BTreeMap,
    fmt::{Formatter, Result as FmtResult},
    path::{Path, PathBuf},
};

use crate::{
    client::files::BRIDGE_DATA_DIRECTORY_NAME,
    commitments::CommitmentMessageId,
    common::ZkProofVerifyingKey,
    connectors::base::*,
    error::{ChunkerError, ConnectorError, Error},
    transactions::base::Input,
    utils::{
        cleanup_cache_files, read_cache, remove_script_and_control_block_from_witness, write_cache,
    },
};
use bitcoin::{
    hashes::{hash160, Hash},
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, Transaction, TxIn, XOnlyPublicKey,
};
use num_traits::ToPrimitive;
use secp256k1::SECP256K1;
use serde::{
    de,
    ser::{Error as SerError, SerializeStruct},
    Deserialize, Deserializer, Serialize, Serializer,
};

use bitvm::{
    chunker::{
        assigner::BridgeAssigner,
        chunk_groth16_verifier::groth16_verify_to_segments,
        common::RawWitness,
        disprove_execution::{disprove_exec, RawProof},
    },
    signatures::signing_winternitz::WinternitzPublicKey,
};

// Specialized for assert leaves currently.
pub type LockScript = fn(index: u32) -> ScriptBuf;
pub type UnlockWitnessData = Vec<u8>;
pub type UnlockWitness = fn(index: u32) -> UnlockWitnessData;

pub struct DisproveLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

const CACHE_DIRECTORY_NAME: &str = "cache";
const LOCK_SCRIPTS_FILE_PREFIX: &str = "lock_scripts_";
const MAX_CACHE_FILES: u32 = 90; //~1GB in total, based on lock scripts cache being 11MB each

fn get_lock_scripts_cache_path(cache_id: &str) -> PathBuf {
    let lock_scripts_file_name = format!("{LOCK_SCRIPTS_FILE_PREFIX}{}.bin", cache_id);
    Path::new(BRIDGE_DATA_DIRECTORY_NAME)
        .join(CACHE_DIRECTORY_NAME)
        .join(lock_scripts_file_name)
}

#[derive(Eq, PartialEq, Clone)]
pub struct ConnectorC {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub lock_scripts_bytes: Vec<Vec<u8>>, // using primitive type for binary serialization, convert to ScriptBuf when using it
    commitment_public_keys: BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
}

impl Serialize for ConnectorC {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut c = s.serialize_struct("ConnectorC", 4)?;
        c.serialize_field("network", &self.network)?;
        c.serialize_field(
            "operator_taproot_public_key",
            &self.operator_taproot_public_key,
        )?;
        c.serialize_field("commitment_public_keys", &self.commitment_public_keys)?;

        let cache_id = Self::cache_id(&self.commitment_public_keys).map_err(SerError::custom)?;
        c.serialize_field("lock_scripts", &cache_id)?;

        let lock_scripts_cache_path = get_lock_scripts_cache_path(&cache_id);
        if !lock_scripts_cache_path.exists() {
            write_cache(&lock_scripts_cache_path, &self.lock_scripts_bytes)
                .map_err(SerError::custom)?;
        }

        cleanup_cache_files(
            LOCK_SCRIPTS_FILE_PREFIX,
            get_lock_scripts_cache_path(&cache_id).parent().unwrap(),
            MAX_CACHE_FILES,
        );

        c.end()
    }
}

impl<'de> Deserialize<'de> for ConnectorC {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct JsonConnectorCVisitor;
        impl<'de> de::Visitor<'de> for JsonConnectorCVisitor {
            type Value = ConnectorC;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("a string containing ConnectorC data")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut operator_taproot_public_key = None;
                let mut commitment_public_keys = None;
                let mut network = None;
                let mut lock_scripts_cache_id = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "network" => network = Some(map.next_value()?),
                        "operator_taproot_public_key" => {
                            operator_taproot_public_key = Some(map.next_value()?)
                        }
                        "commitment_public_keys" => {
                            commitment_public_keys = Some(map.next_value()?)
                        }
                        "lock_scripts" => lock_scripts_cache_id = Some(map.next_value()?),
                        _ => (),
                    }
                }

                match (network, operator_taproot_public_key, commitment_public_keys) {
                    (
                        Some(network),
                        Some(operator_taproot_public_key),
                        Some(commitment_public_keys),
                    ) => Ok(ConnectorC::new(
                        network,
                        &operator_taproot_public_key,
                        &commitment_public_keys,
                        lock_scripts_cache_id,
                    )),
                    _ => Err(de::Error::custom("Invalid ConnectorC data")),
                }
            }
        }

        d.deserialize_struct(
            "ConnectorC",
            &[
                "network",
                "operator_taproot_public_key",
                "commitment_public_keys",
                "lock_scripts",
            ],
            JsonConnectorCVisitor,
        )
    }
}

impl ConnectorC {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
        lock_scripts_cache_id: Option<String>,
    ) -> Self {
        let lock_scripts_cache = lock_scripts_cache_id.and_then(|cache_id| {
            let file_path = get_lock_scripts_cache_path(&cache_id);
            read_cache(&file_path)
                .inspect_err(|e| {
                    eprintln!(
                        "Failed to read lock scripts cache from expected location: {}",
                        e
                    );
                })
                .ok()
        });

        ConnectorC {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            lock_scripts_bytes: lock_scripts_cache
                .unwrap_or_else(|| generate_assert_leaves(commitment_public_keys)),
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
        .ok_or(Error::Chunker(ChunkerError::ValidProof))
    }

    pub fn cache_id(
        commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
    ) -> Result<String, ConnectorError> {
        let first_winternitz_public_key = commitment_public_keys.iter().next();

        match first_winternitz_public_key {
            None => Err(ConnectorError::ConnectorCCommitsPublicKeyEmpty),
            Some((_, winternitz_public_key)) => {
                let hash = hash160::Hash::hash(winternitz_public_key.public_key.as_flattened());
                Ok(hex::encode(hash))
            }
        }
    }
}

impl TaprootConnector for ConnectorC {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        let index = leaf_index.to_usize().unwrap();
        if index >= self.lock_scripts_bytes.len() {
            panic!("Invalid leaf index.")
        }
        ScriptBuf::from_bytes(self.lock_scripts_bytes[index].clone())
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        let index = leaf_index.to_usize().unwrap();
        if index >= self.lock_scripts_bytes.len() {
            panic!("Invalid leaf index.")
        }
        generate_default_tx_in(input)
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        let script_weights = self
            .lock_scripts_bytes
            .iter()
            .map(|b| (1, ScriptBuf::from_bytes(b.clone())));

        TaprootBuilder::with_huffman_tree(script_weights)
            .expect("Unable to add assert leaves")
            .finalize(SECP256K1, self.operator_taproot_public_key)
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
) -> Vec<Vec<u8>> {
    println!("Generating new lock scripts...");
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
        locks.push(segment.script(&bridge_assigner).compile().into_bytes());
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
