use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    client::{
        files::BRIDGE_DATA_DIRECTORY_NAME,
        memory_cache::{TAPROOT_LOCK_SCRIPTS_CACHE, TAPROOT_SPEND_INFO_CACHE},
    },
    commitments::CommitmentMessageId,
    common::ZkProofVerifyingKey,
    connectors::base::*,
    error::{ChunkerError, Error},
    transactions::base::Input,
    utils::{
        cleanup_cache_files, compress, decompress, read_disk_cache,
        remove_script_and_control_block_from_witness, write_disk_cache,
    },
};
use bitcoin::{
    hashes::{hash160, Hash},
    hex::DisplayHex,
    key::TweakedPublicKey,
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapNodeHash, Transaction, TxIn, XOnlyPublicKey,
};
use num_traits::ToPrimitive;
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

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
use zstd::DEFAULT_COMPRESSION_LEVEL;

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

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorC {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    commitment_public_keys: BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
}

impl ConnectorC {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
    ) -> Self {
        assert!(
            !commitment_public_keys.is_empty(),
            "commitment_public_keys is empty"
        );
        ConnectorC {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            commitment_public_keys: commitment_public_keys.clone(),
        }
    }

    pub fn generate_disprove_witness(
        &self,
        commit_1_witness: Vec<RawWitness>,
        commit_2_witness: Vec<RawWitness>,
        vk: &ZkProofVerifyingKey,
    ) -> Result<(usize, RawWitness), Error> {
        println!("Generating disprove witness ...");
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
        let locs: Vec<ScriptBuf> = self
            .lock_scripts_bytes()
            .into_iter()
            .map(|f| {
                ScriptBuf::from_bytes(f)
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
        self.taproot_spend_info_cached().merkle_root
    }

    pub fn taproot_output_key(&self) -> TweakedPublicKey {
        self.taproot_spend_info_cached().output_key
    }

    pub fn taproot_scripts_len(&self) -> usize {
        self.taproot_spend_info_cached().scripts_length
    }

    pub fn taproot_script_and_control_block(&self, leaf_index: usize) -> (ScriptBuf, ControlBlock) {
        let cache_id = lock_script_cache_id(&self.commitment_public_keys, leaf_index);
        let cache = TAPROOT_LOCK_SCRIPTS_CACHE
            .write()
            .unwrap()
            .get_or_put(cache_id, || {
                let (script, control_block) = generate_script_and_control_block(
                    self.operator_taproot_public_key,
                    &self.lock_scripts_bytes(),
                    leaf_index,
                );
                let encoded_data = bitcode::encode(script.as_bytes());
                let compressed_data = compress(&encoded_data, DEFAULT_COMPRESSION_LEVEL)
                    .expect("Unable to compress script for caching");
                LockScriptCacheEntry {
                    control_block,
                    encoded_script: compressed_data,
                }
            })
            .clone();
        decompress(&cache.encoded_script)
            .ok()
            .map(|data| (data, cache.control_block))
            .and_then(|(encoded, control_block)| {
                bitcode::decode::<Vec<u8>>(&encoded)
                    .ok()
                    .map(|decoded| (ScriptBuf::from(decoded), control_block))
            })
            .expect("Cached script data corrupted")
    }

    fn taproot_spend_info_cached(&self) -> TaprootSpendInfoCacheEntry {
        let cache_id = spend_info_cache_id(&self.commitment_public_keys);
        TAPROOT_SPEND_INFO_CACHE
            .write()
            .unwrap()
            .get_or_put(cache_id, || {
                let lock_scripts_bytes = &self.lock_scripts_bytes();
                let spend_info = generate_taproot_spend_info(
                    self.operator_taproot_public_key,
                    lock_scripts_bytes,
                );
                TaprootSpendInfoCacheEntry::new(&spend_info, lock_scripts_bytes.len())
            })
            .clone()
    }

    fn lock_scripts_bytes(&self) -> Vec<Vec<u8>> {
        let cache_id = spend_info_cache_id(&self.commitment_public_keys);
        let file_path = get_lock_scripts_cache_path(&cache_id);
        let lock_scripts_bytes = read_disk_cache(&file_path)
            .inspect_err(|e| {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!(
                        "Failed to read lock scripts cache from expected location: {}",
                        e
                    );
                }
            })
            .unwrap_or_else(|_| generate_assert_leaves(&self.commitment_public_keys));
        if !file_path.exists() {
            write_disk_cache(&file_path, &lock_scripts_bytes)
                .inspect_err(|e| eprintln!("Failed to write lock scripts cache to disk: {}", e))
                .ok();
        }
        cleanup_cache_files(
            LOCK_SCRIPTS_FILE_PREFIX,
            file_path.parent().unwrap(),
            MAX_CACHE_FILES,
        );

        lock_scripts_bytes
    }
}

impl TaprootConnector for ConnectorC {
    fn generate_taproot_leaf_script(&self, _: u32) -> ScriptBuf {
        // use taproot_script_and_control_block to get cached script and control block
        unreachable!("Cache is not used for leaf scripts");
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        let index = leaf_index.to_usize().unwrap();
        if index >= self.taproot_scripts_len() {
            panic!("Invalid leaf index.")
        }
        generate_default_tx_in(input)
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        // use taproot_merkle_root/taproot_output_key/taproot_scripts_len to get cached spend info fields
        unreachable!("Cache is not used for taproot spend info");
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(self.taproot_output_key(), self.network)
    }
}

fn first_winternitz_public_key_bytes(
    commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
) -> Vec<u8> {
    let (_, first_winternitz_public_key) = commitment_public_keys
        .iter()
        .next()
        .expect("commitment_public_keys should not be empty");
    first_winternitz_public_key
        .public_key
        .as_flattened()
        .to_vec()
}

fn spend_info_cache_id(
    commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
) -> String {
    let bytes = first_winternitz_public_key_bytes(commitment_public_keys);
    let hash = hash160::Hash::hash(&bytes);
    hash.as_byte_array().to_lower_hex_string()
}

fn lock_script_cache_id(
    commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
    leaf_index: usize,
) -> String {
    let mut bytes = first_winternitz_public_key_bytes(commitment_public_keys);
    bytes.append(leaf_index.to_be_bytes().to_vec().as_mut());
    let hash = hash160::Hash::hash(&bytes);
    hash.as_byte_array().to_lower_hex_string()
}

fn generate_script_and_control_block(
    operator_taproot_public_key: XOnlyPublicKey,
    lock_scripts_bytes: &Vec<Vec<u8>>,
    leaf_index: usize,
) -> (ScriptBuf, ControlBlock) {
    let spend_info = generate_taproot_spend_info(operator_taproot_public_key, lock_scripts_bytes);
    let script = ScriptBuf::from(lock_scripts_bytes[leaf_index].clone());
    let prevout_leaf = (script, LeafVersion::TapScript);
    let control_block = spend_info
        .control_block(&prevout_leaf)
        .expect("Unable to create Control block");
    (prevout_leaf.0, control_block)
}

fn generate_taproot_spend_info(
    operator_taproot_public_key: XOnlyPublicKey,
    lock_scripts_bytes: &Vec<Vec<u8>>,
) -> TaprootSpendInfo {
    println!("Generating new taproot spend info for connector C...");
    let script_weights = lock_scripts_bytes
        .iter()
        .map(|b| (1, ScriptBuf::from_bytes(b.clone())));
    TaprootBuilder::with_huffman_tree(script_weights)
        .expect("Unable to add assert leaves")
        .finalize(SECP256K1, operator_taproot_public_key)
        .expect("Unable to finalize assert transaction connector c taproot")
}

fn generate_assert_leaves(
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
    let locks =  api_generate_full_tapscripts(pks, &partial_scripts);
    let locks = locks
        .into_iter()
        .map(|f| f.into_bytes())
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
