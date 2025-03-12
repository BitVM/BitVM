use std::str::FromStr;

use bitcoin::{Amount, OutPoint, Txid};

use bridge::{
    error::{Error, ValidationError},
    graphs::{base::PEG_IN_FEE, peg_in::PegInGraph, peg_out::PegOutGraph},
    scripts::generate_burn_script,
    transactions::{base::Input, pre_signed::PreSignedTransaction},
};
use esplora_client::AsyncClient;

use crate::bridge::setup::{setup_test, INITIAL_AMOUNT};

#[tokio::test]
async fn test_validate_success() {
    let (peg_in_graph, peg_out_graph, _, esplora) = setup_and_create_graphs().await;

    let is_peg_in_data_valid = peg_in_graph.validate();
    let is_peg_out_data_valid = peg_out_graph.validate(&esplora).await;

    assert!(is_peg_in_data_valid.is_ok());
    assert!(is_peg_out_data_valid.is_ok());
}

#[tokio::test]
async fn test_validate_invalid_previous_output() {
    let (mut peg_in_graph, _, peg_in_outpoint, _) = setup_and_create_graphs().await;

    let changed_outpoint = OutPoint {
        txid: peg_in_outpoint.txid,
        vout: peg_in_outpoint.vout + 1,
    };
    let deposit_tx = peg_in_graph.peg_in_deposit_transaction.tx_mut();
    deposit_tx.input[0].previous_output = changed_outpoint;

    let result = peg_in_graph.validate();

    let refund_txid = peg_in_graph.peg_in_refund_transaction.tx().compute_txid();
    assert!(matches!(
        result,
        Err(Error::Validation(ValidationError::TxValidationFailed(
            _,
            _,
            _
        )))
    ));

    if let Err(Error::Validation(ValidationError::TxValidationFailed(tx_name, txid, input_index))) =
        result
    {
        assert_eq!(tx_name, "PegInRefund");
        assert_eq!(txid, refund_txid);
        assert_eq!(input_index, 0);
    }
}

#[tokio::test]
async fn test_validate_invalid_script_sig() {
    let (mut peg_in_graph, _, _, _) = setup_and_create_graphs().await;

    let deposit_tx = peg_in_graph.peg_in_deposit_transaction.tx_mut();
    deposit_tx.input[0].script_sig = generate_burn_script();
    let deposit_txid = deposit_tx.compute_txid();

    let result = peg_in_graph.validate();

    assert!(matches!(
        result,
        Err(Error::Validation(ValidationError::TxValidationFailed(
            _,
            _,
            _
        )))
    ));

    if let Err(Error::Validation(ValidationError::TxValidationFailed(tx_name, txid, input_index))) =
        result
    {
        assert_eq!(tx_name, "PegInDeposit");
        assert_eq!(txid, deposit_txid);
        assert_eq!(input_index, 0);
    }
}

#[tokio::test]
async fn test_validate_invalid_sequence() {
    let (mut peg_in_graph, _, _, _) = setup_and_create_graphs().await;

    let deposit_tx = peg_in_graph.peg_in_deposit_transaction.tx_mut();
    deposit_tx.input[0].sequence = bitcoin::Sequence(100);
    let deposit_txid = deposit_tx.compute_txid();

    let result = peg_in_graph.validate();

    assert!(matches!(
        result,
        Err(Error::Validation(ValidationError::TxValidationFailed(
            _,
            _,
            _
        )))
    ));

    if let Err(Error::Validation(ValidationError::TxValidationFailed(tx_name, txid, input_index))) =
        result
    {
        assert_eq!(tx_name, "PegInDeposit");
        assert_eq!(txid, deposit_txid);
        assert_eq!(input_index, 0);
    }
}

#[tokio::test]
async fn test_validate_invalid_value() {
    let (mut peg_in_graph, _, _, _) = setup_and_create_graphs().await;

    let deposit_tx = peg_in_graph.peg_in_deposit_transaction.tx_mut();
    deposit_tx.output[0].value = Amount::from_sat(1);
    let deposit_txid = deposit_tx.compute_txid();

    let result = peg_in_graph.validate();

    assert!(matches!(
        result,
        Err(Error::Validation(ValidationError::TxValidationFailed(
            _,
            _,
            _
        )))
    ));

    if let Err(Error::Validation(ValidationError::TxValidationFailed(tx_name, txid, input_index))) =
        result
    {
        assert_eq!(tx_name, "PegInDeposit");
        assert_eq!(txid, deposit_txid);
        assert_eq!(input_index, 0);
    }
}

#[tokio::test]
async fn test_validate_invalid_script_pubkey() {
    let (mut peg_in_graph, _, _, _) = setup_and_create_graphs().await;

    let deposit_tx = peg_in_graph.peg_in_deposit_transaction.tx_mut();
    deposit_tx.output[0].script_pubkey = generate_burn_script();
    let deposit_txid = deposit_tx.compute_txid();

    let result = peg_in_graph.validate();

    assert!(matches!(
        result,
        Err(Error::Validation(ValidationError::TxValidationFailed(
            _,
            _,
            _
        )))
    ));

    if let Err(Error::Validation(ValidationError::TxValidationFailed(tx_name, txid, input_index))) =
        result
    {
        assert_eq!(tx_name, "PegInDeposit");
        assert_eq!(txid, deposit_txid);
        assert_eq!(input_index, 0);
    }
}

async fn setup_and_create_graphs() -> (PegInGraph, PegOutGraph, OutPoint, AsyncClient) {
    let config = setup_test().await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + PEG_IN_FEE);
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

    let peg_in_graph = PegInGraph::new(
        &config.depositor_context,
        Input {
            outpoint: peg_in_outpoint,
            amount,
        },
        &config.depositor_evm_address,
    );

    let peg_out_graph = PegOutGraph::new(
        &config.operator_context,
        &peg_in_graph,
        Input {
            outpoint: peg_out_outpoint,
            amount,
        },
        &config.commitment_secrets,
    );

    (
        peg_in_graph,
        peg_out_graph,
        peg_in_outpoint,
        config.client_0.esplora,
    )
}
