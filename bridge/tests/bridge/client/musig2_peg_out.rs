use bitcoin::{Address, Amount, OutPoint};
use bitvm::chunk::api::type_conversion_utils::RawProof;
use bridge::{
    client::{
        chain::{
            chain::{Chain, PegOutEvent},
            mock_adaptor::{MockAdaptor, MockAdaptorConfig},
        },
        client::BitVMClient,
    },
    contexts::{
        depositor::DepositorContext, operator::OperatorContext, withdrawer::WithdrawerContext,
    },
    graphs::base::{PEG_IN_FEE, PEG_OUT_FEE},
    scripts::{
        generate_p2pkh_address, generate_pay_to_pubkey_script,
        generate_pay_to_pubkey_script_address,
    },
    transactions::{
        base::{Input, InputWithScript, MIN_RELAY_FEE_DISPROVE},
        pre_signed::PreSignedTransaction,
    },
};
use num_traits::ToPrimitive;
use serial_test::serial;

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{
        find_peg_in_graph_by_peg_out, generate_stub_outpoint, wait_for_confirmation_with_message,
        wait_for_timelock_expiry,
    },
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_take_1() {
    println!("Testing musig2 signing for take 1");
    let (
        mut depositor_operator_verifier_0_client,
        _,
        peg_out_graph_id,
        depositor_context,
        withdrawer_evm_address,
        withdrawer_context,
        operator_context,
        _,
    ) = create_peg_out_graph().await;
    simulate_peg_out_from_l2(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &operator_context,
        &withdrawer_evm_address,
        &withdrawer_context,
    )
    .await;

    let with_kick_off_2_tx = true;
    let with_challenge_tx = false;
    let with_assert_tx = None;
    broadcast_transactions_from_peg_out_graph(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &depositor_context,
        with_kick_off_2_tx,
        with_challenge_tx,
        with_assert_tx,
    )
    .await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_take_1(&peg_out_graph_id)
        .await
        .expect("Failed to broadcast take 1");
}

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_take_2() {
    println!("Testing musig2 signing for take 2");
    let (
        mut depositor_operator_verifier_0_client,
        _,
        peg_out_graph_id,
        depositor_context,
        withdrawer_evm_address,
        withdrawer_context,
        operator_context,
        invalid_proof,
    ) = create_peg_out_graph().await;
    simulate_peg_out_from_l2(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &operator_context,
        &withdrawer_evm_address,
        &withdrawer_context,
    )
    .await;

    let with_kick_off_2_tx = true;
    let with_challenge_tx = false;
    let with_assert_tx = Some(invalid_proof);
    broadcast_transactions_from_peg_out_graph(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &depositor_context,
        with_kick_off_2_tx,
        with_challenge_tx,
        with_assert_tx,
    )
    .await;

    println!("Broadcasting take 2...");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_take_2(&peg_out_graph_id)
        .await
        .expect("Failed to broadcast take 2");
}

#[tokio::test]
#[serial]
async fn test_musig2_start_time_timeout() {
    println!("Testing musig2 signing for start time timeout");
    let (
        mut depositor_operator_verifier_0_client,
        _,
        peg_out_graph_id,
        depositor_context,
        withdrawer_evm_address,
        withdrawer_context,
        operator_context,
        _,
    ) = create_peg_out_graph().await;
    simulate_peg_out_from_l2(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &operator_context,
        &withdrawer_evm_address,
        &withdrawer_context,
    )
    .await;

    let with_kick_off_2_tx = false;
    let with_challenge_tx = false;
    let with_assert_tx = None;
    broadcast_transactions_from_peg_out_graph(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &depositor_context,
        with_kick_off_2_tx,
        with_challenge_tx,
        with_assert_tx,
    )
    .await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_start_time_timeout(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await
        .expect("Failed to broadcast start time timeout");
}

#[tokio::test]
#[serial]
async fn test_musig2_kick_off_timeout() {
    println!("Testing musig2 signing for kick off timeout");
    let (
        mut depositor_operator_verifier_0_client,
        _,
        peg_out_graph_id,
        depositor_context,
        withdrawer_evm_address,
        withdrawer_context,
        operator_context,
        _,
    ) = create_peg_out_graph().await;
    simulate_peg_out_from_l2(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &operator_context,
        &withdrawer_evm_address,
        &withdrawer_context,
    )
    .await;

    let with_kick_off_2_tx = false;
    let with_challenge_tx = false;
    let with_assert_tx = None;
    broadcast_transactions_from_peg_out_graph(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &depositor_context,
        with_kick_off_2_tx,
        with_challenge_tx,
        with_assert_tx,
    )
    .await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_kick_off_timeout(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await
        .expect("Failed to broadcast kick off timeout");
}

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_disprove_with_challenge() {
    println!("Testing musig2 signing for disprove with challenge");
    let (
        mut depositor_operator_verifier_0_client,
        _,
        peg_out_graph_id,
        depositor_context,
        withdrawer_evm_address,
        withdrawer_context,
        operator_context,
        invalid_proof,
    ) = create_peg_out_graph().await;
    simulate_peg_out_from_l2(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &operator_context,
        &withdrawer_evm_address,
        &withdrawer_context,
    )
    .await;

    let with_kick_off_2_tx = true;
    let with_challenge_tx = true;
    let with_assert_tx = Some(invalid_proof);
    broadcast_transactions_from_peg_out_graph(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &depositor_context,
        with_kick_off_2_tx,
        with_challenge_tx,
        with_assert_tx,
    )
    .await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_disprove(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await
        .expect("Failed to broadcast disprove");
}

#[ignore]
#[tokio::test]
#[serial]
async fn test_musig2_peg_out_disprove_chain_with_challenge() {
    println!("Testing musig2 signing for disprove chain with challenge");
    let (
        mut depositor_operator_verifier_0_client,
        _,
        peg_out_graph_id,
        depositor_context,
        withdrawer_evm_address,
        withdrawer_context,
        operator_context,
        _,
    ) = create_peg_out_graph().await;
    simulate_peg_out_from_l2(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &operator_context,
        &withdrawer_evm_address,
        &withdrawer_context,
    )
    .await;

    let with_kick_off_2_tx = true;
    let with_challenge_tx = true;
    let with_assert_tx = None;
    broadcast_transactions_from_peg_out_graph(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &depositor_context,
        with_kick_off_2_tx,
        with_challenge_tx,
        with_assert_tx,
    )
    .await;

    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .broadcast_disprove_chain(
            &peg_out_graph_id,
            generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        )
        .await
        .expect("Failed to broadcast disprove chain");
}

#[tokio::test]
#[serial]
async fn test_musig2_peg_out_peg_out() {
    println!("Testing musig2 signing for peg out");
    let (
        mut depositor_operator_verifier_0_client,
        _,
        peg_out_graph_id,
        _,
        withdrawer_evm_address,
        withdrawer_context,
        operator_context,
        _,
    ) = create_peg_out_graph().await;
    simulate_peg_out_from_l2(
        &mut depositor_operator_verifier_0_client,
        &peg_out_graph_id,
        &operator_context,
        &withdrawer_evm_address,
        &withdrawer_context,
    )
    .await;
}

async fn broadcast_transactions_from_peg_out_graph(
    client: &mut BitVMClient,
    peg_out_graph_id: &String,
    depositor_context: &DepositorContext,
    with_kick_off_2_tx: bool,
    with_challenge_tx: bool,
    with_assert_proof: Option<RawProof>,
) {
    println!("Broadcasting kick-off 1...");
    client.sync().await;
    client
        .broadcast_kick_off_1(peg_out_graph_id)
        .await
        .expect("Failed to broadcast kick-off 1");

    wait_for_timelock_expiry(client.source_network, Some("kick-off 1 connector 1")).await;

    if with_kick_off_2_tx {
        println!("Broadcasting start time...");
        client
            .broadcast_start_time(peg_out_graph_id)
            .await
            .expect("Failed to broadcast start time");

        wait_for_confirmation_with_message(client.source_network, Some("peg-out start time tx"))
            .await;

        println!("Broadcasting kick-off 2...");
        client
            .broadcast_kick_off_2(peg_out_graph_id)
            .await
            .expect("Failed to broadcast kick-off 2");

        wait_for_timelock_expiry(client.source_network, Some("kick-off 2 connector b")).await;
    }

    if with_challenge_tx {
        let challenge_input_amount = Amount::from_btc(1.0).unwrap();
        let challenge_funding_utxo_address = generate_pay_to_pubkey_script_address(
            depositor_context.network,
            &depositor_context.depositor_public_key,
        );
        let faucet = Faucet::new(FaucetType::EsploraRegtest);
        faucet
            .fund_input(&challenge_funding_utxo_address, challenge_input_amount)
            .await
            .wait()
            .await;

        let challenge_funding_outpoint = generate_stub_outpoint(
            client,
            &challenge_funding_utxo_address,
            challenge_input_amount,
        )
        .await;
        let challenge_crowdfunding_input = InputWithScript {
            outpoint: challenge_funding_outpoint,
            amount: challenge_input_amount,
            script: &generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
        };
        println!("Broadcasting challenge...");
        client
            .broadcast_challenge(
                peg_out_graph_id,
                &vec![challenge_crowdfunding_input],
                generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
            )
            .await
            .expect("Failed to broadcast challenge");

        wait_for_confirmation_with_message(client.source_network, Some("peg-out challenge tx"))
            .await;
    }

    if let Some(assert_proof) = with_assert_proof {
        println!("Broadcasting assert initial...");
        client
            .broadcast_assert_initial(&peg_out_graph_id)
            .await
            .expect("Failed to broadcast assert initial");
        wait_for_confirmation_with_message(
            client.source_network,
            Some("peg-out assert initial tx"),
        )
        .await;

        println!("Broadcasting assert commit 1...");
        client
            .broadcast_assert_commit_1(&peg_out_graph_id, &assert_proof)
            .await
            .expect("Failed to broadcast assert commit 1");
        wait_for_confirmation_with_message(
            client.source_network,
            Some("peg-out assert commit 1 tx"),
        )
        .await;

        println!("Broadcasting assert commit 2...");
        client
            .broadcast_assert_commit_2(&peg_out_graph_id, &assert_proof)
            .await
            .expect("Failed to broadcast assert commit 2");
        wait_for_confirmation_with_message(
            client.source_network,
            Some("peg-out assert commit 2 tx"),
        )
        .await;

        println!("Broadcasting assert final...");
        client
            .broadcast_assert_final(&peg_out_graph_id)
            .await
            .expect("Failed to broadcast assert final");
        wait_for_timelock_expiry(client.source_network, Some("assert final connector 4")).await;
    }
}

async fn create_peg_out_graph() -> (
    BitVMClient,
    BitVMClient,
    String,
    DepositorContext,
    String,
    WithdrawerContext,
    OperatorContext,
    RawProof,
) {
    let config = setup_test().await;
    let mut depositor_operator_verifier_0_client = config.client_0;
    let mut verifier_1_client = config.client_1;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let deposit_input_amount = Amount::from_sat(INITIAL_AMOUNT + PEG_IN_FEE + MIN_RELAY_FEE_DISPROVE);
    let deposit_funding_address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    funding_inputs.push((&deposit_funding_address, deposit_input_amount));

    let kick_off_input_amount = Amount::from_sat(INITIAL_AMOUNT + PEG_OUT_FEE + MIN_RELAY_FEE_DISPROVE);
    let kick_off_funding_utxo_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );
    funding_inputs.push((&kick_off_funding_utxo_address, kick_off_input_amount));

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    faucet
        .fund_inputs(&depositor_operator_verifier_0_client, &funding_inputs)
        .await
        .wait()
        .await;

    let kick_off_outpoint = generate_stub_outpoint(
        &depositor_operator_verifier_0_client,
        &kick_off_funding_utxo_address,
        kick_off_input_amount,
    )
    .await;

    println!("Creating peg-in graph...");
    // create and complete peg-in graph
    let peg_in_graph_id = create_peg_in_graph(
        &mut depositor_operator_verifier_0_client,
        deposit_funding_address,
        deposit_input_amount,
        &config.depositor_evm_address,
    )
    .await;

    println!("Creating peg-out graph...");
    let peg_out_graph_id = depositor_operator_verifier_0_client.create_peg_out_graph(
        &peg_in_graph_id,
        Input {
            outpoint: kick_off_outpoint,
            amount: kick_off_input_amount,
        },
        config.commitment_secrets,
    );

    println!("Verifier 0 push peg-out nonces");
    depositor_operator_verifier_0_client
        .process_peg_in_as_verifier(&peg_in_graph_id) // verifier 0 push nonces
        .await;
    depositor_operator_verifier_0_client.flush().await;

    println!("Verifier 1 push peg-out nonces");
    verifier_1_client.sync().await;
    verifier_1_client
        .process_peg_in_as_verifier(&peg_in_graph_id)
        .await;
    verifier_1_client.flush().await;

    println!("Verifier 0 pre-sign peg-out");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .process_peg_in_as_verifier(&peg_in_graph_id)
        .await;
    depositor_operator_verifier_0_client.flush().await;

    println!("Verifier 1 pre-sign peg-out");
    verifier_1_client.sync().await;
    verifier_1_client
        .process_peg_in_as_verifier(&peg_in_graph_id)
        .await;
    verifier_1_client.flush().await;

    println!("Verifier 0 broadcast peg-in confirm");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client
        .process_peg_in_as_verifier(&peg_in_graph_id)
        .await;

    (
        depositor_operator_verifier_0_client,
        verifier_1_client,
        peg_out_graph_id,
        config.depositor_context,
        config.withdrawer_evm_address,
        config.withdrawer_context,
        config.operator_context,
        config.invalid_proof,
    )
}

async fn create_peg_in_graph(
    client_0: &mut BitVMClient,
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
    println!("Peg in graph created: {}", graph_id);

    client_0
        .broadcast_peg_in_deposit(&graph_id)
        .await
        .expect("Failed to broadcast peg-in deposit");
    wait_for_confirmation_with_message(client_0.source_network, Some("peg-in deposit tx")).await;

    graph_id
}

async fn simulate_peg_out_from_l2(
    client: &mut BitVMClient,
    peg_out_graph_id: &String,
    operator_context: &OperatorContext,
    withdrawer_evm_address: &String,
    withdrawer_context: &WithdrawerContext,
) {
    let peg_in_graph = find_peg_in_graph_by_peg_out(client, peg_out_graph_id).unwrap();
    let peg_in_confirm = peg_in_graph.peg_in_confirm_transaction_ref();
    let peg_in_confirm_vout: usize = 0;
    println!(
        "peg_in_confirm_txid: {:?}",
        peg_in_confirm.tx().compute_txid()
    );
    let peg_in_confirm_amount = peg_in_confirm.tx().output[peg_in_confirm_vout].value;

    let mock_adaptor_config = MockAdaptorConfig {
        peg_out_init_events: Some(vec![PegOutEvent {
            source_outpoint: OutPoint {
                txid: peg_in_confirm.tx().compute_txid(),
                vout: peg_in_confirm_vout.to_u32().unwrap(),
            },
            amount: peg_in_confirm_amount,
            timestamp: 1722328130u32,
            withdrawer_chain_address: withdrawer_evm_address.clone(),
            withdrawer_destination_address: generate_p2pkh_address(
                withdrawer_context.network,
                &withdrawer_context.withdrawer_public_key,
            )
            .to_string(),
            withdrawer_public_key_hash: withdrawer_context.withdrawer_public_key.pubkey_hash(),
            operator_public_key: operator_context.operator_public_key,
            tx_hash: [0u8; 4].into(),
        }]),
        peg_out_burnt_events: None,
        peg_out_minted_events: None,
    };
    let mock_adaptor = MockAdaptor::new(Some(mock_adaptor_config));
    let chain_service = Chain::new(Box::new(mock_adaptor));

    client.set_chain_service(chain_service);
    client.sync_l2().await;

    let operator_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    println!(
        "operator_funding_utxo_address: {:?}",
        operator_funding_utxo_address
    );
    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    faucet
        .fund_input(&operator_funding_utxo_address, peg_in_confirm_amount)
        .await
        .wait()
        .await;
    let operator_funding_outpoint = generate_stub_outpoint(
        client,
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

    println!("Broadcasting peg out...");
    client
        .broadcast_peg_out(peg_out_graph_id, input)
        .await
        .expect("Failed to broadcast peg out");

    wait_for_confirmation_with_message(client.source_network, Some("peg-out tx")).await;

    println!("Broadcasting peg out confirm...");
    client
        .broadcast_peg_out_confirm(peg_out_graph_id)
        .await
        .expect("Failed to broadcast peg out confirm");

    wait_for_confirmation_with_message(client.source_network, Some("peg-out confirm tx")).await;
}
