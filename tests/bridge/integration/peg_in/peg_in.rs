use std::time::Duration;

use bitcoin::{Amount, OutPoint};

use bitvm::bridge::{
    connectors::{connector::TaprootConnector, connector_0::Connector0},
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_confirm::PegInConfirmTransaction,
        peg_in_deposit::PegInDepositTransaction,
        peg_in_refund::PegInRefundTransaction,
    },
};
use esplora_client::Error;
use tokio::time::sleep;

use crate::bridge::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_in_success() {
    let (
        client,
        _,
        depositor_context,
        _,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test().await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT * 2;
    let deposit_input_amount = Amount::from_sat(input_amount_raw);

    // peg-in deposit
    let deposit_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    let deposit_funding_outpoint =
        generate_stub_outpoint(&client, &deposit_funding_utxo_address, deposit_input_amount).await;
    let deposit_input = Input {
        outpoint: deposit_funding_outpoint,
        amount: deposit_input_amount,
    };

    let peg_in_deposit =
        PegInDepositTransaction::new(&depositor_context, &depositor_evm_address, deposit_input);

    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();

    // mine peg-in deposit
    let deposit_result = client.esplora.broadcast(&peg_in_deposit_tx).await;
    assert!(deposit_result.is_ok());
    println!("Deposit Txid: {:?}", deposit_txid);

    // peg-in confirm
    let output_index = 0;
    let confirm_funding_outpoint = OutPoint {
        txid: deposit_txid,
        vout: output_index,
    };
    let confirm_input = Input {
        outpoint: confirm_funding_outpoint,
        amount: peg_in_deposit_tx.output[output_index as usize].value,
    };
    let mut peg_in_confirm =
        PegInConfirmTransaction::new(&depositor_context, &depositor_evm_address, confirm_input);

    let secret_nonces_0 = peg_in_confirm.push_nonces(&verifier_0_context);
    let secret_nonces_1 = peg_in_confirm.push_nonces(&verifier_1_context);

    peg_in_confirm.pre_sign(&verifier_0_context, &secret_nonces_0);
    peg_in_confirm.pre_sign(&verifier_1_context, &secret_nonces_1);

    let peg_in_confirm_tx = peg_in_confirm.finalize();
    let confirm_txid = peg_in_confirm_tx.compute_txid();

    // mine peg-in confirm
    let confirm_result = client.esplora.broadcast(&peg_in_confirm_tx).await;
    assert!(confirm_result.is_ok());
    println!("Confirm Txid: {:?}", confirm_txid);

    // multi-sig balance
    let connector_0 = Connector0::new(
        depositor_context.network,
        &depositor_context.n_of_n_taproot_public_key,
    );
    let multi_sig_address = connector_0.generate_taproot_address();
    let multi_sig_utxos = client
        .esplora
        .get_address_utxo(multi_sig_address.clone())
        .await
        .unwrap();
    let multi_sig_utxo = multi_sig_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == confirm_txid);

    // assert
    assert!(multi_sig_utxo.is_some());
    assert_eq!(
        multi_sig_utxo.unwrap().value,
        peg_in_confirm_tx.output[0].value,
    );
    assert_eq!(
        peg_in_confirm_tx.output[0].value,
        Amount::from_sat(INITIAL_AMOUNT),
    );
}

#[tokio::test]
async fn test_peg_in_time_lock_not_surpassed() {
    let (
        client,
        _,
        depositor_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test().await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT * 2;
    let deposit_input_amount = Amount::from_sat(input_amount_raw);

    // peg-in deposit
    let deposit_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    let deposit_funding_outpoint =
        generate_stub_outpoint(&client, &deposit_funding_utxo_address, deposit_input_amount).await;
    let deposit_input = Input {
        outpoint: deposit_funding_outpoint,
        amount: deposit_input_amount,
    };

    let peg_in_deposit =
        PegInDepositTransaction::new(&depositor_context, &depositor_evm_address, deposit_input);
    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();

    // mine peg-in deposit
    let deposit_result = client.esplora.broadcast(&peg_in_deposit_tx).await;
    assert!(deposit_result.is_ok());

    // peg-in refund
    let output_index = 0;
    let refund_funding_outpoint = OutPoint {
        txid: deposit_txid,
        vout: output_index,
    };
    let refund_input = Input {
        outpoint: refund_funding_outpoint,
        amount: peg_in_deposit_tx.output[output_index as usize].value,
    };
    let peg_in_refund =
        PegInRefundTransaction::new(&depositor_context, &depositor_evm_address, refund_input);
    let peg_in_refund_tx = peg_in_refund.finalize();

    // mine peg-in refund
    let refund_result = client.esplora.broadcast(&peg_in_refund_tx).await;
    assert!(refund_result.is_err());
    let error = refund_result.unwrap_err();
    let expected_error = Error::HttpResponse {
        status: 400,
        message: String::from(
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"non-BIP68-final\"}",
        ), // indicates that relative timelock based on sequence numbers has not elapsed
    };
    assert_eq!(error.to_string(), expected_error.to_string());
}

#[tokio::test]
async fn test_peg_in_time_lock_surpassed() {
    let (
        client,
        _,
        depositor_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test().await;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT * 2;
    let deposit_input_amount = Amount::from_sat(input_amount_raw);

    // peg-in deposit
    let deposit_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    let deposit_funding_outpoint =
        generate_stub_outpoint(&client, &deposit_funding_utxo_address, deposit_input_amount).await;
    let deposit_input = Input {
        outpoint: deposit_funding_outpoint,
        amount: deposit_input_amount,
    };

    let peg_in_deposit =
        PegInDepositTransaction::new(&depositor_context, &depositor_evm_address, deposit_input);
    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();

    // mine peg-in deposit
    let deposit_result = client.esplora.broadcast(&peg_in_deposit_tx).await;
    assert!(deposit_result.is_ok());

    // peg-in refund
    let output_index = 0;
    let refund_funding_outpoint = OutPoint {
        txid: deposit_txid,
        vout: output_index,
    };
    let refund_input = Input {
        outpoint: refund_funding_outpoint,
        amount: peg_in_deposit_tx.output[output_index as usize].value,
    };
    let peg_in_refund =
        PegInRefundTransaction::new(&depositor_context, &depositor_evm_address, refund_input);
    let peg_in_refund_tx = peg_in_refund.finalize();
    let refund_txid = peg_in_refund_tx.compute_txid();

    // mine peg-in refund
    sleep(Duration::from_secs(60)).await; // TODO: check if this can be refactored to drop waiting
    let refund_result = client.esplora.broadcast(&peg_in_refund_tx).await;
    assert!(refund_result.is_ok());

    // depositor balance
    let depositor_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    let depositor_utxos = client
        .esplora
        .get_address_utxo(depositor_address.clone())
        .await
        .unwrap();
    let depositor_utxo = depositor_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == refund_txid);

    // assert
    assert!(depositor_utxo.is_some());
    assert_eq!(
        depositor_utxo.unwrap().value,
        peg_in_refund_tx.output[0].value
    );
    assert_eq!(
        peg_in_refund_tx.output[0].value,
        Amount::from_sat(INITIAL_AMOUNT),
    );
}
