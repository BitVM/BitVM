use std::{
    collections::BTreeMap,
    fmt::{Formatter, Result as FmtResult},
    path::{Path, PathBuf},
};

use crate::{
    client::{files::BRIDGE_DATA_DIRECTORY_NAME, memory_cache::TAPROOT_SPEND_INFO_CACHE},
    commitments::CommitmentMessageId,
    common::ZkProofVerifyingKey,
    connectors::base::*,
    error::{ChunkerError, ConnectorError, Error},
    transactions::base::Input,
    utils::{
        cleanup_cache_files, read_disk_cache, remove_script_and_control_block_from_witness,
        write_disk_cache,
    },
};
use bitcoin::{
    hashes::{hash160, Hash},
    key::TweakedPublicKey,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapNodeHash, Transaction, TxIn, XOnlyPublicKey,
};
use num_traits::ToPrimitive;
use secp256k1::SECP256K1;
use serde::{
    de,
    ser::{Error as SerError, SerializeStruct},
    Deserialize, Deserializer, Serialize, Serializer,
};

use bitvm::{
    chunk::api::{
        api_generate_full_tapscripts, api_generate_partial_script,
        type_conversion_utils::{
            script_to_witness, utils_signatures_from_raw_witnesses, utils_typed_pubkey_from_raw,
            RawProof, RawWitness,
        },
        validate_assertions, PublicKeys,
    },
    // chunker::{
    //     assigner::BridgeAssigner,
    //     chunk_groth16_verifier::groth16_verify_to_segments,
    //     common::RawWitness,
    //     disprove_execution::{disprove_exec, RawProof},
    // },
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
            write_disk_cache(&lock_scripts_cache_path, &self.lock_scripts_bytes)
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
            read_disk_cache(&file_path)
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
        let mut sorted_pks: Vec<(u32, WinternitzPublicKey)> = vec![];
        self.commitment_public_keys
            .clone()
            .into_iter()
            .for_each(|(k, v)| {
                if let CommitmentMessageId::Groth16IntermediateValues((name, _)) = k {
                    let index = u32::from_str_radix(&name, 10).unwrap();
                    sorted_pks.push((index, v));
                }
            });
        sorted_pks.sort_by(|a, b| a.0.cmp(&b.0));
        let sorted_pks = sorted_pks
            .iter()
            .map(|f| &f.1)
            .collect::<Vec<&WinternitzPublicKey>>();

        let mut commit_witness = commit_1_witness.clone();
        commit_witness.extend_from_slice(&commit_2_witness);

        let sigs = utils_signatures_from_raw_witnesses(&commit_witness);
        let pubs = utils_typed_pubkey_from_raw(sorted_pks);
        let locs: Vec<bitcoin_script::builder::StructuredScript> = self
            .lock_scripts_bytes
            .clone()
            .into_iter()
            .map(|f| {
                bitcoin_script::builder::StructuredScript::new("")
                    .push_script(ScriptBuf::from_bytes(f))
            })
            .collect();
        let locs = locs.try_into().unwrap();
        let exec_res = validate_assertions(vk, sigs, pubs, &locs);
        if exec_res.is_some() {
            let exec_res = exec_res.unwrap();
            let wit: RawWitness = script_to_witness(exec_res.1);
            return Ok((exec_res.0, wit));
        }
        return Err(Error::Chunker(ChunkerError::ValidProof));
    }

    pub fn taproot_merkle_root(&self) -> Option<TapNodeHash> {
        self.taproot_spend_info_cache()
            .map(|cache| cache.merkle_root)
            .unwrap_or_else(|| self.generate_taproot_spend_info().merkle_root())
    }

    pub fn taproot_output_key(&self) -> TweakedPublicKey {
        self.taproot_spend_info_cache()
            .map(|cache| cache.output_key)
            .unwrap_or_else(|| self.generate_taproot_spend_info().output_key())
    }

    // read from cache or generate from [`TaprootConnector`]
    fn taproot_spend_info_cache(&self) -> Option<TaprootSpendInfoCache> {
        let spend_info_cache = match Self::cache_id(&self.commitment_public_keys).map(|cache_id| {
            TAPROOT_SPEND_INFO_CACHE
                .read()
                .unwrap()
                .get(&cache_id)
                .cloned()
        }) {
            Ok(Some(spend_info_cache)) => Some(spend_info_cache),
            Ok(None) => {
                let spend_info = self.generate_taproot_spend_info();
                let output_key = spend_info.output_key();
                let spend_info_cache = TaprootSpendInfoCache {
                    merkle_root: spend_info.merkle_root(),
                    output_key,
                };
                Some(spend_info_cache)
            }
            _ => None,
        };

        spend_info_cache
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
        println!("Generating new taproot spend info for connector C...");
        let script_weights = self
            .lock_scripts_bytes
            .iter()
            .map(|b| (1, ScriptBuf::from_bytes(b.clone())));

        let spend_info = TaprootBuilder::with_huffman_tree(script_weights)
            .expect("Unable to add assert leaves")
            .finalize(SECP256K1, self.operator_taproot_public_key)
            .expect("Unable to finalize assert transaction connector c taproot");

        // write to cache
        if let Ok(cache_id) = Self::cache_id(&self.commitment_public_keys) {
            let output_key = spend_info.output_key();
            let spend_info_cache = TaprootSpendInfoCache {
                merkle_root: spend_info.merkle_root(),
                output_key,
            };
            if !TAPROOT_SPEND_INFO_CACHE.read().unwrap().contains(&cache_id) {
                TAPROOT_SPEND_INFO_CACHE
                    .write()
                    .unwrap()
                    .push(cache_id, spend_info_cache);
            }
        }

        spend_info
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(self.taproot_output_key(), self.network)
    }
}

pub fn generate_assert_leaves(
    commits_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
) -> Vec<Vec<u8>> {
    println!("Generating new lock scripts...");
    // hash map to btree map
    let mut sorted_pks: Vec<(u32, WinternitzPublicKey)> = vec![];
    commits_public_keys.clone().into_iter().for_each(|(k, v)| {
        if let CommitmentMessageId::Groth16IntermediateValues((name, _)) = k {
            let index = u32::from_str_radix(&name, 10).unwrap();
            sorted_pks.push((index, v));
        }
    });

    sorted_pks.sort_by(|a, b| a.0.cmp(&b.0));
    let sorted_pks = sorted_pks
        .iter()
        .map(|f| &f.1)
        .collect::<Vec<&WinternitzPublicKey>>();

    let default_proof = RawProof::default(); // mock a default proof to generate scripts
    let partial_scripts = api_generate_partial_script(&default_proof.vk);
    let pks: PublicKeys = utils_typed_pubkey_from_raw(sorted_pks);
    let locks = api_generate_full_tapscripts(pks, &partial_scripts);
    let locks = locks
        .into_iter()
        .map(|f| f.compile().into_bytes())
        .collect();
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
