use std::str::FromStr;

use bitcoin::{Amount, OutPoint, Txid};
use bitvm::bridge::{
    client::client::{BitVMClient, BitVMClientPublicData},
    graphs::{
        base::{FEE_AMOUNT, INITIAL_AMOUNT},
        peg_in::PegInGraph,
        peg_out::PegOutGraph,
    },
    transactions::base::Input,
};

use crate::bridge::setup::setup_test;

#[tokio::test]
// TODO: test merging signatures after Musig2 feature is ready
async fn test_merge_add_new_graph() {
    let (mut client, new_peg_in_graph, new_peg_out_graph) = setup_and_create_graphs().await;

    let data = client.get_data();
    let new_data = BitVMClientPublicData {
        version: data.version + 1,
        peg_in_graphs: vec![new_peg_in_graph.clone()],
        peg_out_graphs: vec![new_peg_out_graph.clone()],
    };

    assert_eq!(data.peg_in_graphs.len(), 1);
    assert_eq!(data.peg_out_graphs.len(), 1);

    client.merge_data(new_data);

    let merged_data = client.get_data();

    let merged_data_peg_in_graph = merged_data
        .peg_in_graphs
        .iter()
        .find(|&graph| graph.eq(&new_peg_in_graph));
    let merged_data_peg_out_graph = merged_data
        .peg_out_graphs
        .iter()
        .find(|&graph| graph.eq(&new_peg_out_graph));

    assert!(merged_data_peg_in_graph.is_some());
    assert!(merged_data_peg_out_graph.is_some());
    assert_eq!(merged_data.peg_in_graphs.len(), 2);
    assert_eq!(merged_data.peg_out_graphs.len(), 2);
}

async fn setup_and_create_graphs() -> (BitVMClient, PegInGraph, PegOutGraph) {
    let mut config = setup_test().await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT + 1);
    let peg_in_outpoint = OutPoint {
        txid: Txid::from_str("0e6719ac074b0e3cac76d057643506faa1c266b322aa9cf4c6f635fe63b14327")
            .unwrap(),
        vout: 0,
    };
    let peg_out_outpoint = OutPoint {
        txid: Txid::from_str("4e254eab8a41f14f56491813a7100cebe305d84edf09488001d9dd3d180a4900")
            .unwrap(),
        vout: 0,
    };

    let input = Input {
        outpoint: peg_in_outpoint,
        amount,
    };
    let peg_in_graph_id = config
        .client_0
        .create_peg_in_graph(input, &config.depositor_evm_address)
        .await;

    config
        .client_0
        .create_peg_out_graph(
            &peg_in_graph_id,
            Input {
                outpoint: peg_out_outpoint,
                amount,
            },
        )
        .await;

    let new_peg_in_graph = PegInGraph::new(
        &config.depositor_context,
        Input {
            outpoint: peg_in_outpoint,
            amount: Amount::from_sat(INITIAL_AMOUNT),
        },
        &config.depositor_evm_address,
    );

    let (new_peg_out_graph, _) = PegOutGraph::new(
        &config.operator_context,
        &new_peg_in_graph,
        Input {
            outpoint: peg_out_outpoint,
            amount,
        },
    );

    return (config.client_0, new_peg_in_graph, new_peg_out_graph);
}
