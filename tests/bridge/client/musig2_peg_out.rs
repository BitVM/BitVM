use std::time::Duration;

use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    client::{
        chain::chain::{Chain, PegOutEvent},
        client::BitVMClient,
    },
    contexts::{
        depositor::DepositorContext, operator::OperatorContext, withdrawer::WithdrawerContext,
    },
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{Input, InputWithScript},
        pre_signed::PreSignedTransaction,
    },
};
use num_traits::ToPrimitive;
use serial_test::serial;
use tokio::time::sleep;

use crate::bridge::{
    faucet::Faucet,
    helper::{find_peg_in_graph_by_peg_out, generate_stub_outpoint, TX_WAIT_TIME},
    mock::chain::mock::MockAdaptor,
    setup::setup_test,
};

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_take_1() {
    let with_kick_off_2_tx = false;
    let with_challenge_tx = false;
    let with_assert_tx = false;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, _, _, _, _) =
        create_peg_out_graph(with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_take_1(&peg_out_graph_id)
        .await;
}

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_take_2() {
    let with_kick_off_2_tx = true;
    let with_challenge_tx = false;
    let with_assert_tx = true;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, _, _, _, _) =
        create_peg_out_graph(with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    eprintln!("Broadcasting take 2...");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_take_2(&peg_out_graph_id)
        .await;
}

#[tokio::test]
#[serial]
async fn test_musig2_start_time_timeout() {
    let with_kick_off_2_tx = false;
    let with_challenge_tx = false;
    let with_assert_tx = false;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, depositor_context, _, _, _) =
        create_peg_out_graph(with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_start_time_timeout(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await;
}

#[tokio::test]
#[serial]
async fn test_musig2_kick_off_timeout() {
    let with_kick_off_2_tx = false;
    let with_challenge_tx = false;
    let with_assert_tx = false;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, depositor_context, _, _, _) =
        create_peg_out_graph(with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_kick_off_timeout(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await;
}

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_disprove_with_challenge() {
    let with_kick_off_2_tx = true;
    let with_challenge_tx = true;
    let with_assert_tx = true;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, depositor_context, _, _, _) =
        create_peg_out_graph(with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_disprove(
            &peg_out_graph_id,
            1,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await;
}

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_disprove_chain_with_challenge() {
    let with_kick_off_2_tx = true;
    let with_challenge_tx = true;
    let with_assert_tx = false;
    let (mut depositor_operator_verifier_0_client, _, peg_out_graph_id, depositor_context, _, _, _) =
        create_peg_out_graph(with_kick_off_2_tx, with_challenge_tx, with_assert_tx).await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_disprove_chain(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await;
}

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_peg_out() {
    let (
        mut depositor_operator_verifier_0_client,
        _,
        peg_out_graph_id,
        _,
        withdrawer_evm_address,
        withdrawer_context,
        operator_context,
    ) = create_peg_out_graph(false, false, false).await;
    depositor_operator_verifier_0_client.sync().await;
    let peg_in_graph =
        find_peg_in_graph_by_peg_out(&depositor_operator_verifier_0_client, &peg_out_graph_id)
            .unwrap();
    let peg_in_confirm = peg_in_graph.peg_in_confirm_transaction_ref();
    let peg_in_confirm_vout: usize = 0;
    println!(
        "peg_in_confirm_txid: {:?}",
        peg_in_confirm.tx().compute_txid()
    );
    let peg_in_confirm_amount = peg_in_confirm.tx().output[peg_in_confirm_vout].value;

    let mut mock_adaptor = MockAdaptor::new();
    mock_adaptor.peg_out_init_events = vec![PegOutEvent {
        source_outpoint: OutPoint {
            txid: peg_in_confirm.tx().compute_txid(),
            vout: peg_in_confirm_vout.to_u32().unwrap(),
        },
        amount: peg_in_confirm_amount,
        timestamp: 1722328130u32,
        withdrawer_chain_address: withdrawer_evm_address,
        withdrawer_public_key_hash: withdrawer_context.withdrawer_public_key.pubkey_hash(),
        operator_public_key: operator_context.operator_public_key,
        tx_hash: [0u8; 4].into(),
    }];
    let mut chain_adaptor = Chain::new();
    chain_adaptor.init_default(Box::new(mock_adaptor));
    depositor_operator_verifier_0_client.set_chain_adaptor(chain_adaptor);
    depositor_operator_verifier_0_client.sync_l2().await;

    let operator_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    println!(
        "operator_funding_utxo_address: {:?}",
        operator_funding_utxo_address
    );
    let faucet = Faucet::new();
    faucet
        .fund_input_and_wait(&operator_funding_utxo_address, peg_in_confirm_amount)
        .await;
    let operator_funding_outpoint = generate_stub_outpoint(
        &depositor_operator_verifier_0_client,
        &operator_funding_utxo_address,
        peg_in_confirm_amount,
    )
    .await;
    println!(
        "operator_funding_utxo.txid: {:?}",
        operator_funding_outpoint.txid
    );
    let input = Input {
        outpoint: operator_funding_outpoint,
        amount: peg_in_confirm_amount,
    };
    eprintln!("Broadcasting peg out...");
    depositor_operator_verifier_0_client
        .broadcast_peg_out(&peg_out_graph_id, input)
        .await;
}

async fn create_peg_out_graph(
    with_kick_off_2_tx: bool,
    with_challenge_tx: bool,
    with_assert_tx: bool,
) -> (
    BitVMClient,
    BitVMClient,
    String,
    DepositorContext,
    String,
    WithdrawerContext,
    OperatorContext,
) {
    let config = setup_test().await;
    let mut depositor_operator_verifier_0_client = config.client_0;
    let mut verifier_1_client = config.client_1;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let deposit_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let deposit_funding_address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    funding_inputs.push((&deposit_funding_address, deposit_input_amount));

    let kick_off_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_funding_utxo_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );
    funding_inputs.push((&kick_off_funding_utxo_address, kick_off_input_amount));

    let challenge_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let challenge_funding_utxo_address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    if with_challenge_tx {
        funding_inputs.push((&challenge_funding_utxo_address, challenge_input_amount));
    }

    let faucet = Faucet::new();
    faucet
        .verify_and_fund_inputs(&depositor_operator_verifier_0_client, &funding_inputs)
        .await;
    println!("Waiting for funding inputs tx...");
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;

    let kick_off_outpoint = generate_stub_outpoint(
        &depositor_operator_verifier_0_client,
        &kick_off_funding_utxo_address,
        kick_off_input_amount,
    )
    .await;

    eprintln!("Creating peg-in graph...");
    // create and complete peg-in graph
    let peg_in_graph_id = create_peg_in_graph(
        &mut depositor_operator_verifier_0_client,
        &mut verifier_1_client,
        deposit_funding_address,
        deposit_input_amount,
        &config.depositor_evm_address,
    )
    .await;

    eprintln!("Creating peg-out graph...");
    depositor_operator_verifier_0_client.sync().await;
    let peg_out_graph_id = depositor_operator_verifier_0_client
        .create_peg_out_graph(
            &peg_in_graph_id,
            Input {
                outpoint: kick_off_outpoint,
                amount: kick_off_input_amount,
            },
        )
        .await;

    eprintln!("Verifier 0 push peg-out nonces");
    depositor_operator_verifier_0_client.push_peg_out_nonces(&peg_out_graph_id);
    depositor_operator_verifier_0_client.flush().await;

    eprintln!("Verifier 1 push peg-out nonces");
    verifier_1_client.sync().await;
    verifier_1_client.push_peg_out_nonces(&peg_out_graph_id);
    verifier_1_client.flush().await;

    eprintln!("Verifier 0 pre-sign peg-out");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client.pre_sign_peg_out(&peg_out_graph_id);
    depositor_operator_verifier_0_client.flush().await;

    eprintln!("Verifier 1 pre-sign peg-out");
    verifier_1_client.sync().await;
    verifier_1_client.pre_sign_peg_out(&peg_out_graph_id);
    verifier_1_client.flush().await;

    eprintln!("Broadcasting kick-off 1...");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_kick_off_1(&peg_out_graph_id)
        .await;

    // Wait for peg-in deposit transaction to be mined
    println!("Waiting for peg-out kick-off tx...");
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;

    if with_kick_off_2_tx {
        eprintln!("Broadcasting start time...");
        depositor_operator_verifier_0_client
            .broadcast_start_time(&peg_out_graph_id)
            .await;

        println!("Waiting for peg-out start time tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;

        eprintln!("Broadcasting kick-off 2...");
        depositor_operator_verifier_0_client
            .broadcast_kick_off_2(&peg_out_graph_id)
            .await;

        println!("Waiting for peg-out kick-off 2 tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;
    }

    if with_challenge_tx {
        let challenge_funding_outpoint = generate_stub_outpoint(
            &depositor_operator_verifier_0_client,
            &challenge_funding_utxo_address,
            challenge_input_amount,
        )
        .await;
        let challenge_crowdfunding_input = InputWithScript {
            outpoint: challenge_funding_outpoint,
            amount: challenge_input_amount,
            script: &generate_pay_to_pubkey_script(&config.depositor_context.depositor_public_key),
        };
        eprintln!("Broadcasting challenge...");
        depositor_operator_verifier_0_client
            .broadcast_challenge(
                &peg_out_graph_id,
                &vec![challenge_crowdfunding_input],
                generate_pay_to_pubkey_script(&config.depositor_context.depositor_public_key),
            )
            .await;

        println!("Waiting for peg-out challenge tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;
    }

    if with_assert_tx {
        eprintln!("Broadcasting assert...");
        depositor_operator_verifier_0_client
            .broadcast_assert(&peg_out_graph_id)
            .await;

        println!("Waiting for peg-out assert tx...");
        sleep(Duration::from_secs(TX_WAIT_TIME)).await;
    }

    (
        depositor_operator_verifier_0_client,
        verifier_1_client,
        peg_out_graph_id,
        config.depositor_context,
        config.withdrawer_evm_address,
        config.withdrawer_context,
        config.operator_context,
    )
}

async fn create_peg_in_graph(
    client_0: &mut BitVMClient,
    client_1: &mut BitVMClient,
    deposit_funding_address: Address,
    deposit_amount: Amount,
    depositor_evm_address: &String,
) -> String {
    let deposit_outpoint =
        generate_stub_outpoint(client_0, &deposit_funding_address, deposit_amount).await;
    let graph_id = client_0
        .create_peg_in_graph(
            Input {
                outpoint: deposit_outpoint,
                amount: deposit_amount,
            },
            depositor_evm_address,
        )
        .await;

    client_0.broadcast_peg_in_deposit(&graph_id).await;
    client_0.push_peg_in_nonces(&graph_id);
    client_0.flush().await;

    client_1.sync().await;
    client_1.push_peg_in_nonces(&graph_id);
    client_1.flush().await;

    client_0.sync().await;
    client_0.pre_sign_peg_in(&graph_id);
    client_0.flush().await;

    client_1.sync().await;
    client_1.pre_sign_peg_in(&graph_id);
    client_1.flush().await;

    // Wait for peg-in deposit transaction to be mined
    println!("Waiting for peg-in deposit tx...");
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;

    client_0.sync().await;
    client_0.broadcast_peg_in_confirm(&graph_id).await;
    client_0.flush().await;

    graph_id
}
