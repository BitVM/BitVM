use std::{borrow::Cow, collections::BTreeMap, str::FromStr, time::Duration};

use ark_bn254::G1Affine;
use ark_ff::UniformRand;
use ark_std::test_rng;
use bitcoin::{
    block::{Header, Version},
    hex::{Case::Lower, DisplayHex},
    Address, Amount, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Transaction,
    TxMerkleNode,
};

use bitvm::{
    bridge::{
        client::client::BitVMClient,
        connectors::connector_c::generate_assert_leaves,
        graphs::{
            base::{BaseGraph, REWARD_MULTIPLIER, REWARD_PRECISION},
            peg_in::PegInGraph,
            peg_out::{CommitmentMessageId, PegOutGraph},
        },
        transactions::signing_winternitz::WinternitzPublicKey,
        utils::num_blocks_per_network,
    },
    chunker::{assigner::BridgeAssigner, disprove_execution::RawProof},
};
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

pub const TX_WAIT_TIME: u64 = 5; // in seconds
pub const ESPLORA_FUNDING_URL: &str = "https://esploraapi53d3659b.devnet-annapurna.stratabtc.org/";
pub const ESPLORA_RETRIES: usize = 3;
pub const ESPLORA_RETRY_WAIT_TIME: u64 = 5;

pub const TX_RELAY_FEE_CHECK_FAIL_MSG: &str =
    "Output sum should be equal to initial amount, check MIN_RELAY_FEE_* definitions?";
pub fn check_tx_output_sum(input_amount_without_relay_fee: u64, tx: &Transaction) {
    assert_eq!(
        input_amount_without_relay_fee,
        tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>(),
        "{TX_RELAY_FEE_CHECK_FAIL_MSG}"
    );
}

pub fn get_reward_amount(initial_amount: u64) -> u64 {
    initial_amount * REWARD_MULTIPLIER / REWARD_PRECISION
}

pub async fn wait_for_confirmation() {
    let timeout = Duration::from_secs(TX_WAIT_TIME);
    println!("Waiting {:?} for tx confirmation...", timeout);
    sleep(timeout).await;
}

pub async fn wait_timelock_expiry(network: Network, timelock_name: Option<&str>) {
    let timeout = Duration::from_secs(TX_WAIT_TIME * num_blocks_per_network(network, 0) as u64);
    println!(
        "Waiting \x1b[37;41m{:?}\x1b[0m {} to timeout ...",
        timeout,
        match timelock_name {
            Some(timelock_name) => format!("for {}", timelock_name),
            None => "".to_string(),
        }
    );
    sleep(timeout).await;
}

pub async fn generate_stub_outpoint(
    client: &BitVMClient,
    funding_utxo_address: &Address,
    input_value: Amount,
) -> OutPoint {
    let funding_utxo = client
        .get_initial_utxo(funding_utxo_address.clone(), input_value)
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at {}",
                funding_utxo_address,
                input_value.to_sat(),
                ESPLORA_FUNDING_URL,
            );
        });
    OutPoint {
        txid: funding_utxo.txid,
        vout: funding_utxo.vout,
    }
}

pub async fn generate_stub_outpoints(
    client: &BitVMClient,
    funding_utxo_address: &Address,
    input_value: Amount,
) -> Vec<OutPoint> {
    let funding_utxos = client
        .get_initial_utxos(funding_utxo_address.clone(), input_value)
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at {}",
                funding_utxo_address,
                input_value.to_sat(),
                ESPLORA_FUNDING_URL,
            );
        });
    funding_utxos
        .iter()
        .map(|utxo| OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        })
        .collect()
}

pub async fn verify_funding_inputs(client: &BitVMClient, funding_inputs: &Vec<(&Address, Amount)>) {
    let mut inputs_to_fund: Vec<(&Address, Amount)> = vec![];

    for funding_input in funding_inputs {
        if client
            .get_initial_utxo(funding_input.0.clone(), funding_input.1)
            .await
            .is_none()
        {
            inputs_to_fund.push((funding_input.0, funding_input.1));
        }
    }

    for input_to_fund in inputs_to_fund.clone() {
        println!(
            "Fund {:?} with {} sats at {}",
            input_to_fund.0,
            input_to_fund.1.to_sat(),
            ESPLORA_FUNDING_URL,
        );
    }
    if !inputs_to_fund.is_empty() {
        panic!("You need to fund {} addresses first.", inputs_to_fund.len());
    }
}

pub fn find_peg_in_graph(client: &BitVMClient, peg_in_graph_id: &str) -> Option<PegInGraph> {
    let peg_in_graph = client
        .data()
        .peg_in_graphs
        .iter()
        .find(|&graph| graph.id().eq(peg_in_graph_id));

    peg_in_graph.cloned()
}

pub fn find_peg_out_graph(client: &BitVMClient, peg_out_graph_id: &str) -> Option<PegOutGraph> {
    let peg_out_graph = client
        .data()
        .peg_out_graphs
        .iter()
        .find(|&graph| graph.id().eq(&peg_out_graph_id));

    peg_out_graph.cloned()
}

pub fn find_peg_in_graph_by_peg_out(
    client: &BitVMClient,
    peg_out_graph_id: &str,
) -> Option<PegInGraph> {
    let peg_out_graph = find_peg_out_graph(client, peg_out_graph_id);
    match peg_out_graph {
        Some(peg_out_graph) => find_peg_in_graph(client, &peg_out_graph.peg_in_graph_id),
        None => None,
    }
}

pub fn get_superblock_header() -> Header {
    Header {
        version: Version::from_consensus(0x200d2000),
        prev_blockhash: BlockHash::from_str(
            "000000000000000000027c9f5b07f21e39ba31aa4d900d519478bdac32f4a15d",
        )
        .unwrap(),
        merkle_root: TxMerkleNode::from_str(
            "0064b0d54f20412756ba7ce07b0594f3548b06f2dad5cfeaac2aca508634ed19",
        )
        .unwrap(),
        time: 1729251961,
        bits: CompactTarget::from_hex("0x17030ecd").unwrap(),
        nonce: 0x400e345c,
    }
}

pub fn random_hex<'a>(size: usize) -> Cow<'a, str> {
    let mut buffer = vec![0u8; size];
    let mut rng = rand::rngs::OsRng;
    rand::RngCore::fill_bytes(&mut rng, &mut buffer);
    Cow::Owned(buffer.to_hex_string(Lower))
}

pub fn get_intermediate_variables_cached() -> BTreeMap<String, usize> {
    let intermediate_variables_cache_file_path = std::path::Path::new("cache/intermediates.json");
    match intermediate_variables_cache_file_path.exists() {
        true => read_cache(intermediate_variables_cache_file_path),
        false => {
            let all_variables = BridgeAssigner::default().all_intermediate_variables();
            write_cache(intermediate_variables_cache_file_path, &all_variables).unwrap();
            all_variables
        }
    }
}

pub fn get_lock_scripts_cached(
    commits_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
) -> Vec<ScriptBuf> {
    let lock_scripts_cache_file_path = std::path::Path::new("cache/locks.json");
    match lock_scripts_cache_file_path.exists() {
        true => read_cache(lock_scripts_cache_file_path),
        false => {
            let locks = generate_assert_leaves(commits_public_keys);
            write_cache(lock_scripts_cache_file_path, &locks).unwrap();
            locks
        }
    }
}

pub fn write_cache(file_path: &std::path::Path, data: &impl Serialize) -> std::io::Result<()> {
    println!("Writing cache to {}...", file_path.to_str().unwrap());
    let path_only = file_path
        .to_str()
        .unwrap()
        .replace(file_path.file_name().unwrap().to_str().unwrap(), "");
    if !std::path::Path::new(path_only.as_str()).exists() {
        std::fs::create_dir_all(path_only).expect("Failed to create directories");
    }
    let file = std::fs::File::create(file_path)?;
    let file = std::io::BufWriter::new(file);
    serde_json::to_writer(file, data)?;
    Ok(())
}

pub fn read_cache<T>(file_path: &std::path::Path) -> T
where
    T: for<'a> Deserialize<'a>,
{
    println!("Reading cache from {}...", file_path.to_str().unwrap());
    let file = std::fs::File::open(file_path).expect("Failed to open file");
    let file = std::io::BufReader::new(file);
    serde_json::from_reader(file).expect("Failed to read file")
}

pub fn get_correct_proof() -> RawProof {
    let correct_proof = RawProof::default();
    assert!(correct_proof.valid_proof());
    correct_proof
}

pub fn get_incorrect_proof() -> RawProof {
    let mut correct_proof = get_correct_proof();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    correct_proof.proof.a = G1Affine::rand(&mut rng);

    correct_proof
}
