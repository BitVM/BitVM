use std::time::Duration;

use bitcoin::{Amount, OutPoint};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::generate_stub_outpoint,
    setup::{setup_test, SetupConfig},
};
use bitvm::bridge::{
    client::client::BitVMClient,
    connectors::{base::TaprootConnector, connector_0::Connector0},
    graphs::{
        base::{BaseGraph, FEE_AMOUNT, INITIAL_AMOUNT},
        peg_in::PegInVerifierStatus,
    },
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_confirm::PegInConfirmTransaction,
        peg_in_deposit::PegInDepositTransaction,
        peg_in_refund::PegInRefundTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};
use esplora_client::Error;
use tokio::time::sleep;

#[tokio::test]
async fn test_peg_in_success() {
    let config = setup_test().await;
    let deposit_input = get_pegin_input(&config, INITIAL_AMOUNT + FEE_AMOUNT * 2).await;

    let peg_in_deposit = PegInDepositTransaction::new(
        &config.depositor_context,
        &config.connector_z,
        deposit_input,
    );

    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();

    // mine peg-in deposit
    let deposit_result = config.client_0.esplora.broadcast(&peg_in_deposit_tx).await;
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
    let mut peg_in_confirm = PegInConfirmTransaction::new(
        &config.depositor_context,
        &config.connector_0,
        &config.connector_z,
        confirm_input,
    );

    let secret_nonces_0 = peg_in_confirm.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = peg_in_confirm.push_nonces(&config.verifier_1_context);

    peg_in_confirm.pre_sign(
        &config.verifier_0_context,
        &config.connector_z,
        &secret_nonces_0,
    );
    peg_in_confirm.pre_sign(
        &config.verifier_1_context,
        &config.connector_z,
        &secret_nonces_1,
    );

    let peg_in_confirm_tx = peg_in_confirm.finalize();
    let confirm_txid = peg_in_confirm_tx.compute_txid();

    // mine peg-in confirm
    let confirm_result = config.client_0.esplora.broadcast(&peg_in_confirm_tx).await;
    assert!(confirm_result.is_ok());
    println!("Confirm Txid: {:?}", confirm_txid);

    // multi-sig balance
    let connector_0 = Connector0::new(
        config.depositor_context.network,
        &config.depositor_context.n_of_n_taproot_public_key,
    );
    let multi_sig_address = connector_0.generate_taproot_address();
    let multi_sig_utxos = config
        .client_0
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
    let config = setup_test().await;
    let deposit_input = get_pegin_input(&config, INITIAL_AMOUNT + FEE_AMOUNT * 2).await;

    let peg_in_deposit = PegInDepositTransaction::new(
        &config.depositor_context,
        &config.connector_z,
        deposit_input,
    );
    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();

    // mine peg-in deposit
    let deposit_result = config.client_0.esplora.broadcast(&peg_in_deposit_tx).await;
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
        PegInRefundTransaction::new(&config.depositor_context, &config.connector_z, refund_input);
    let peg_in_refund_tx = peg_in_refund.finalize();

    // mine peg-in refund
    let refund_result = config.client_0.esplora.broadcast(&peg_in_refund_tx).await;
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
    let config = setup_test().await;
    let deposit_input = get_pegin_input(&config, INITIAL_AMOUNT + FEE_AMOUNT * 2).await;

    let peg_in_deposit = PegInDepositTransaction::new(
        &config.depositor_context,
        &config.connector_z,
        deposit_input,
    );
    let peg_in_deposit_tx = peg_in_deposit.finalize();
    let deposit_txid = peg_in_deposit_tx.compute_txid();

    // mine peg-in deposit
    let deposit_result = config.client_0.esplora.broadcast(&peg_in_deposit_tx).await;
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
        PegInRefundTransaction::new(&config.depositor_context, &config.connector_z, refund_input);
    let peg_in_refund_tx = peg_in_refund.finalize();
    let refund_txid = peg_in_refund_tx.compute_txid();

    // mine peg-in refund
    let refund_wait_timeout = Duration::from_secs(60);
    println!(
        "Waiting \x1b[37;41m{:?}\x1b[0m before broadcasting peg in refund tx...",
        refund_wait_timeout
    );
    sleep(refund_wait_timeout).await; // TODO: check if this can be refactored to drop waiting
    let refund_result = config.client_0.esplora.broadcast(&peg_in_refund_tx).await;
    assert!(refund_result.is_ok());

    // depositor balance
    let depositor_address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    let depositor_utxos = config
        .client_0
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

async fn get_pegin_input(config: &SetupConfig, sats: u64) -> Input {
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let deposit_input_amount = Amount::from_sat(sats);
    // peg-in deposit
    let deposit_funding_utxo_address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    println!(
        "deposit_funding_utxo_address: {:?}",
        deposit_funding_utxo_address
    );
    faucet
        .fund_input(&deposit_funding_utxo_address, deposit_input_amount)
        .await
        .wait()
        .await;

    let deposit_funding_outpoint = generate_stub_outpoint(
        &config.client_0,
        &deposit_funding_utxo_address,
        deposit_input_amount,
    )
    .await;
    println!(
        "deposit_funding_outpoint.txid: {:?}",
        deposit_funding_outpoint.txid
    );
    Input {
        outpoint: deposit_funding_outpoint,
        amount: deposit_input_amount,
    }
}

#[tokio::test]
async fn test_peg_in_graph_automatic_verifier() {
    // helper functions
    let sync = |a: &mut BitVMClient, b: &mut BitVMClient| {
        a.merge_data(b.get_data().clone());
        b.merge_data(a.get_data().clone());
    };
    let graph = |client: &BitVMClient| client.get_data().peg_in_graphs[0].clone();
    let pegouts_of = |client: &BitVMClient| {
        let pegin = graph(client);
        pegin
            .peg_out_graphs
            .iter()
            .map(|id| {
                client
                    .get_data()
                    .peg_out_graphs
                    .iter()
                    .find(|peg_out| peg_out.id() == id)
                    .unwrap()
                    .clone()
            })
            .collect::<Vec<_>>()
    };
    // set up data
    let mut config = setup_test().await;
    let deposit_input = get_pegin_input(&config, INITIAL_AMOUNT + FEE_AMOUNT * 2).await;
    let client_0 = &mut config.client_0;
    let client_1 = &mut config.client_1;
    let esplora = client_0.esplora.clone();
    let context = Some(&config.verifier_0_context);

    // create the actual graph & check that status changes to PegInWait
    client_0
        .create_peg_in_graph(deposit_input, "0000000000000000000000000000000000000000")
        .await;
    assert_eq!(
        graph(client_0)
            .verifier_status(&esplora, context, &[])
            .await,
        PegInVerifierStatus::AwaitingDeposit
    );

    // wait peg-in deposit and wait for the tx to be confirmed (which will set status to PegInPendingOurNonces)
    client_0.process_peg_in_as_depositor(&graph(client_0)).await;
    loop {
        if !matches!(
            graph(client_0)
                .verifier_status(&esplora, context, &[])
                .await,
            PegInVerifierStatus::AwaitingDeposit
        ) {
            break;
        }
        println!("Awaiting confirmation...");
        sleep(Duration::from_secs(1)).await;
    }

    assert_eq!(
        graph(client_0)
            .verifier_status(&esplora, context, &[])
            .await,
        PegInVerifierStatus::AwaitingPegOutCreation
    );

    // make operator submit a pegout graph & check that status changes to PegInWait
    client_0.process_peg_in_as_operator(&graph(client_0)).await;
    let peg_out_graph = client_0
        .get_data()
        .peg_out_graphs.first()
        .expect("peg out should have been created above")
        .clone();
    let peg_out_graph_id = peg_out_graph.id();
    assert_eq!(
        graph(client_0)
            .verifier_status(
                &esplora,
                context,
                &pegouts_of(client_0).iter().collect::<Vec<_>>()
            )
            .await,
        PegInVerifierStatus::PendingOurNonces(vec![
            peg_out_graph_id.clone(),
            graph(client_0).id().clone()
        ])
    );

    // submit client_0 nonce & check that status changes to PegInAwaitingNonces
    client_0.process_peg_in_as_verifier(&graph(client_0)).await;
    sync(client_0, client_1);
    assert_eq!(
        graph(client_0)
            .verifier_status(
                &esplora,
                context,
                &pegouts_of(client_0).iter().collect::<Vec<_>>()
            )
            .await,
        PegInVerifierStatus::AwaitingNonces
    );

    // submit client_1 nonce & check that status changes to PegInPendingOurSignature
    client_1.process_peg_in_as_verifier(&graph(client_0)).await;
    sync(client_0, client_1);
    assert!(matches!(
        graph(client_0)
            .verifier_status(
                &esplora,
                context,
                &pegouts_of(client_0).iter().collect::<Vec<_>>()
            )
            .await,
        PegInVerifierStatus::PendingOurSignature(_)
    ));

    // submit client_0 signature & check that status changes to PegInAwaitingSignatures
    client_0.process_peg_in_as_verifier(&graph(client_0)).await;
    sync(client_0, client_1);
    assert_eq!(
        graph(client_0)
            .verifier_status(
                &esplora,
                context,
                &pegouts_of(client_0).iter().collect::<Vec<_>>()
            )
            .await,
        PegInVerifierStatus::AwaitingSignatures
    );

    // submit client_1 signature & check that status changes to PegInPresign
    client_1.process_peg_in_as_verifier(&graph(client_0)).await;
    sync(client_0, client_1);
    assert_eq!(
        graph(client_0)
            .verifier_status(
                &esplora,
                context,
                &pegouts_of(client_0).iter().collect::<Vec<_>>()
            )
            .await,
        PegInVerifierStatus::ReadyToSubmit
    );

    // submit confirm tx & check that status changes to PegInComplete
    client_0.process_peg_in_as_verifier(&graph(client_0)).await;
    loop {
        if graph(client_0)
            .verifier_status(
                &esplora,
                context,
                &pegouts_of(client_0).iter().collect::<Vec<_>>(),
            )
            .await
            == PegInVerifierStatus::Complete
        {
            break;
        }
        println!("Awaiting confirmation...");
        sleep(Duration::from_secs(1)).await;
    }
}
