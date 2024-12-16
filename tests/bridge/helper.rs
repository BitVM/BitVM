use std::str::FromStr;

use bitcoin::{
    block::{Header, Version},
    Address, Amount, BlockHash, CompactTarget, OutPoint, TxMerkleNode,
};

use bitvm::bridge::{
    client::client::BitVMClient,
    graphs::{base::BaseGraph, peg_in::PegInGraph, peg_out::PegOutGraph},
};

pub const TX_WAIT_TIME: u64 = 45; // in seconds
pub const ESPLORA_FUNDING_URL: &str = "https://esploraapi53d3659b.devnet-annapurna.stratabtc.org/";
pub const ESPLORA_RETRIES: usize = 3;
pub const ESPLORA_RETRY_WAIT_TIME: u64 = 5;

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
    if inputs_to_fund.len() > 0 {
        panic!("You need to fund {} addresses first.", inputs_to_fund.len());
    }
}

pub fn find_peg_in_graph(client: &BitVMClient, peg_in_graph_id: &str) -> Option<PegInGraph> {
    let peg_in_graph = client
        .get_data()
        .peg_in_graphs
        .iter()
        .find(|&graph| graph.id().eq(peg_in_graph_id));

    match peg_in_graph {
        Some(peg_in_graph) => Some(peg_in_graph.clone()),
        None => None,
    }
}

pub fn find_peg_out_graph(client: &BitVMClient, peg_out_graph_id: &str) -> Option<PegOutGraph> {
    let peg_out_graph = client
        .get_data()
        .peg_out_graphs
        .iter()
        .find(|&graph| graph.id().eq(&peg_out_graph_id));

    match peg_out_graph {
        Some(peg_out_graph) => Some(peg_out_graph.clone()),
        None => None,
    }
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
