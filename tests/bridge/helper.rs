use std::{str::FromStr, time::Duration};

use bitcoin::{
    block::{Header, Version},
    Address, Amount, BlockHash, CompactTarget, Network, OutPoint, Transaction, TxMerkleNode,
};

use bitvm::bridge::{
    client::client::BitVMClient,
    graphs::{
        base::{BaseGraph, REWARD_MULTIPLIER, REWARD_PRECISION},
        peg_in::PegInGraph,
        peg_out::PegOutGraph,
    },
    utils::num_blocks_per_network,
};
use tokio::time::sleep;

pub const TX_WAIT_TIME: u64 = 45; // in seconds
pub const ESPLORA_FUNDING_URL: &str = "https://esploraapi53d3659b.devnet-annapurna.stratabtc.org/";
pub const ESPLORA_RETRIES: usize = 3;
pub const ESPLORA_RETRY_WAIT_TIME: u64 = 5;

pub const TX_RELAY_FEE_CHECK_FAIL_MSG: &str =
    "Output sum should be equal to initial amount, check MIN_RELAY_FEE_* definitions?";
pub fn check_relay_fee(input_amount_without_relay_fee: u64, tx: &Transaction) {
    assert_eq!(
        input_amount_without_relay_fee,
        tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>(),
        "{TX_RELAY_FEE_CHECK_FAIL_MSG}"
    );
}

pub fn get_reward_amount(initial_amount: u64) -> u64 {
    initial_amount * REWARD_MULTIPLIER / REWARD_PRECISION
}

pub async fn wait_for_timelock_to_timeout(network: Network, timelock_name: Option<&str>) {
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
        .get_data()
        .peg_in_graphs
        .iter()
        .find(|&graph| graph.id().eq(peg_in_graph_id));

    peg_in_graph.map(|peg_in_graph| peg_in_graph.clone())
}

pub fn find_peg_out_graph(client: &BitVMClient, peg_out_graph_id: &str) -> Option<PegOutGraph> {
    let peg_out_graph = client
        .get_data()
        .peg_out_graphs
        .iter()
        .find(|&graph| graph.id().eq(&peg_out_graph_id));

    peg_out_graph.map(|peg_out_graph| peg_out_graph.clone())
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
