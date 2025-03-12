use std::str::FromStr;

use bitcoin::{Amount, OutPoint, Txid};

use bridge::{
    client::client::{BitVMClient, BitVMClientPublicData},
    graphs::{base::PEG_OUT_FEE, peg_in::PegInGraph, peg_out::PegOutGraph},
    scripts::generate_burn_script,
    transactions::{base::Input, pre_signed::PreSignedTransaction},
};
use esplora_client::AsyncClient;

use crate::bridge::setup::{setup_test, INITIAL_AMOUNT};

#[tokio::test]
async fn test_validate_success() {
    let (esplora, data, _) = setup_and_create_graphs().await;

    let result = BitVMClient::validate_data(&esplora, &data).await;

    assert!(result);
}

#[tokio::test]
async fn test_validate_invalid_previous_output() {
    let (esplora, mut data, peg_in_outpoint) = setup_and_create_graphs().await;

    let changed_outpoint = OutPoint {
        txid: peg_in_outpoint.txid,
        vout: peg_in_outpoint.vout + 1,
    };

    let deposit_tx = data.peg_in_graphs[1].peg_in_deposit_transaction.tx_mut();
    deposit_tx.input[0].previous_output = changed_outpoint;

    let result = BitVMClient::validate_data(&esplora, &data).await;

    assert!(!result);
}

#[tokio::test]
async fn test_validate_invalid_script_sig() {
    let (esplora, mut data, _) = setup_and_create_graphs().await;

    let deposit_tx = data.peg_in_graphs[1].peg_in_deposit_transaction.tx_mut();
    deposit_tx.input[0].script_sig = generate_burn_script();

    let result = BitVMClient::validate_data(&esplora, &data).await;

    assert!(!result);
}

#[tokio::test]
async fn test_validate_invalid_sequence() {
    let (esplora, mut data, _) = setup_and_create_graphs().await;

    let deposit_tx = data.peg_in_graphs[1].peg_in_deposit_transaction.tx_mut();
    deposit_tx.input[0].sequence = bitcoin::Sequence(100);

    let result = BitVMClient::validate_data(&esplora, &data).await;

    assert!(!result);
}

#[tokio::test]
async fn test_validate_invalid_value() {
    let (esplora, mut data, _) = setup_and_create_graphs().await;

    let deposit_tx = data.peg_in_graphs[1].peg_in_deposit_transaction.tx_mut();
    deposit_tx.output[0].value = Amount::from_sat(1);

    let result = BitVMClient::validate_data(&esplora, &data).await;

    assert!(!result);
}

#[tokio::test]
async fn test_validate_invalid_script_pubkey() {
    let (esplora, mut data, _) = setup_and_create_graphs().await;

    let deposit_tx = data.peg_in_graphs[1].peg_in_deposit_transaction.tx_mut();
    deposit_tx.output[0].script_pubkey = generate_burn_script();

    let result = BitVMClient::validate_data(&esplora, &data).await;

    assert!(!result);
}

async fn setup_and_create_graphs() -> (AsyncClient, BitVMClientPublicData, OutPoint) {
    let config = setup_test().await;

    let amount_0 = Amount::from_sat(INITIAL_AMOUNT + PEG_OUT_FEE + 1);
    let amount_1 = Amount::from_sat(INITIAL_AMOUNT + PEG_OUT_FEE - 1);
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

    let peg_in_graph_0 = PegInGraph::new(
        &config.depositor_context,
        Input {
            outpoint: peg_in_outpoint,
            amount: amount_0,
        },
        &config.depositor_evm_address,
    );

    let peg_in_graph_1 = PegInGraph::new(
        &config.depositor_context,
        Input {
            outpoint: peg_in_outpoint,
            amount: amount_1,
        },
        &config.depositor_evm_address,
    );

    let peg_out_graph = PegOutGraph::new(
        &config.operator_context,
        &peg_in_graph_0,
        Input {
            outpoint: peg_out_outpoint,
            amount: amount_0,
        },
        &config.commitment_secrets,
    );

    let data = BitVMClientPublicData {
        version: 1,
        peg_in_graphs: vec![peg_in_graph_0, peg_in_graph_1],
        peg_out_graphs: vec![peg_out_graph],
    };

    (config.client_0.esplora, data, peg_in_outpoint)
}
