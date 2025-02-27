use bitcoin::{Address, Amount, OutPoint};
use bridge::{
    client::{
        chain::{
            chain::{Chain, PegOutEvent},
            mock_adaptor::{MockAdaptor, MockAdaptorConfig},
        },
        client::BitVMClient,
    },
    commitments::CommitmentMessageId,
    graphs::{
        base::{max, BaseGraph, DUST_AMOUNT, MIN_RELAY_FEE_ASSERT_SET, PEG_IN_FEE, PEG_OUT_FEE},
        peg_in::PegInGraph,
        peg_out::PegOutGraph,
    },
    scripts::{
        generate_p2pkh_address, generate_pay_to_pubkey_script,
        generate_pay_to_pubkey_script_address,
    },
    transactions::{
        base::{
            Input, InputWithScript, MIN_RELAY_FEE_ASSERT_INITIAL, MIN_RELAY_FEE_CHALLENGE,
            MIN_RELAY_FEE_DISPROVE, MIN_RELAY_FEE_DISPROVE_CHAIN, MIN_RELAY_FEE_KICK_OFF_1,
            MIN_RELAY_FEE_KICK_OFF_2, MIN_RELAY_FEE_KICK_OFF_TIMEOUT, MIN_RELAY_FEE_PEG_IN_CONFIRM,
            MIN_RELAY_FEE_PEG_IN_REFUND, MIN_RELAY_FEE_PEG_OUT, MIN_RELAY_FEE_PEG_OUT_CONFIRM,
            MIN_RELAY_FEE_START_TIME, MIN_RELAY_FEE_START_TIME_TIMEOUT, MIN_RELAY_FEE_TAKE_1,
            MIN_RELAY_FEE_TAKE_2,
        },
        pre_signed::PreSignedTransaction,
    },
};
use num_traits::ToPrimitive;

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{
        check_tx_output_sum, find_peg_in_graph_by_peg_out, generate_stub_outpoint,
        get_reward_amount, wait_for_confirmation, wait_for_timelock_expiry,
    },
    setup::{setup_test, INITIAL_AMOUNT, ONE_HUNDRED},
};

#[tokio::test]
async fn test_peg_in_fees() {
    let mut config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount = Amount::from_sat(INITIAL_AMOUNT + PEG_IN_FEE);
    let address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    faucet.fund_input(&address, amount).await.wait().await;
    let peg_in_outpoint = generate_stub_outpoint(&config.client_0, &address, amount).await;

    let peg_in_input = Input {
        outpoint: peg_in_outpoint,
        amount,
    };
    let peg_in_graph_id = config
        .client_0
        .create_peg_in_graph(peg_in_input, &config.depositor_evm_address)
        .await;

    let esplora_client = config.client_0.esplora.clone();

    let peg_in_graph = get_peg_in_graph_mut(&mut config.client_0, peg_in_graph_id.clone());
    let peg_in_deposit_tx = peg_in_graph.deposit(&esplora_client).await.unwrap();
    check_tx_output_sum(
        INITIAL_AMOUNT + max(MIN_RELAY_FEE_PEG_IN_CONFIRM, MIN_RELAY_FEE_PEG_IN_REFUND),
        &peg_in_deposit_tx,
    );
    let deposit_result = esplora_client.broadcast(&peg_in_deposit_tx).await;
    println!("Deposit result: {deposit_result:?}");
    assert!(deposit_result.is_ok());
    config
        .client_0
        .process_peg_in_as_verifier(&peg_in_graph_id)
        .await;
    config.client_0.flush().await;

    config.client_1.sync().await;
    config
        .client_1
        .process_peg_in_as_verifier(&peg_in_graph_id)
        .await;

    let peg_in_graph = get_peg_in_graph_mut(&mut config.client_0, peg_in_graph_id.clone());
    wait_for_timelock_expiry(config.network, Some("peg-in deposit connector z")).await;
    let peg_in_confirm_tx = peg_in_graph.confirm(&esplora_client).await.unwrap();
    check_tx_output_sum(
        INITIAL_AMOUNT + max(MIN_RELAY_FEE_PEG_IN_CONFIRM, MIN_RELAY_FEE_PEG_IN_REFUND)
            - MIN_RELAY_FEE_PEG_IN_CONFIRM,
        &peg_in_confirm_tx,
    );

    let peg_in_refund_tx = peg_in_graph.refund(&esplora_client).await.unwrap();
    check_tx_output_sum(
        INITIAL_AMOUNT + max(MIN_RELAY_FEE_PEG_IN_CONFIRM, MIN_RELAY_FEE_PEG_IN_REFUND)
            - MIN_RELAY_FEE_PEG_IN_REFUND,
        &peg_in_refund_tx,
    );
}

#[tokio::test]
async fn test_peg_out_fees() {
    let mut config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let peg_in_amount = Amount::from_sat(INITIAL_AMOUNT + PEG_IN_FEE);
    let peg_in_funding_address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );

    let peg_out_amount = Amount::from_sat(ONE_HUNDRED + MIN_RELAY_FEE_PEG_OUT);
    let reward_amount = get_reward_amount(ONE_HUNDRED);
    let peg_out_confirm_input_amount = Amount::from_sat(reward_amount + PEG_OUT_FEE);
    let peg_out_funding_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );

    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    funding_inputs.push((&peg_in_funding_address, peg_in_amount));
    funding_inputs.push((&peg_out_funding_address, peg_out_amount));
    funding_inputs.push((&peg_out_funding_address, peg_out_confirm_input_amount));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    let peg_in_outpoint =
        generate_stub_outpoint(&config.client_0, &peg_in_funding_address, peg_in_amount).await;
    let peg_out_outpoint =
        generate_stub_outpoint(&config.client_0, &peg_out_funding_address, peg_out_amount).await;
    let peg_out_confirm_outpoint = generate_stub_outpoint(
        &config.client_0,
        &peg_out_funding_address,
        peg_out_confirm_input_amount,
    )
    .await;

    let peg_in_graph_id = config
        .client_0
        .create_peg_in_graph(
            Input {
                outpoint: peg_in_outpoint,
                amount: peg_in_amount,
            },
            &config.depositor_evm_address,
        )
        .await;
    let peg_out_graph_id = config.client_0.create_peg_out_graph(
        &peg_in_graph_id,
        Input {
            outpoint: peg_out_confirm_outpoint,
            amount: peg_out_confirm_input_amount,
        },
        config.commitment_secrets.clone(),
    );

    let esplora_client = config.client_0.esplora.clone();
    config
        .client_0
        .broadcast_peg_in_deposit(&peg_in_graph_id)
        .await
        .expect("Failed to broadcast peg-in deposit");
    wait_for_timelock_expiry(config.network, Some("peg-in deposit connector z")).await;

    println!(
        "musig2 signing for peg-in: {} and its related peg-out: {}",
        peg_in_graph_id, peg_out_graph_id
    );
    config
        .client_0
        .process_peg_in_as_verifier(&peg_in_graph_id) // verifier 0 push nonces
        .await;
    config.client_0.flush().await;

    config.client_1.sync().await;
    config
        .client_1
        .process_peg_in_as_verifier(&peg_in_graph_id) // verifier 1 push nonces
        .await;
    config.client_1.flush().await;

    config.client_0.sync().await;
    config
        .client_0
        .process_peg_in_as_verifier(&peg_in_graph_id) // verifier 0 push signature
        .await;
    config.client_0.flush().await;

    config.client_1.sync().await;
    config
        .client_1
        .process_peg_in_as_verifier(&peg_in_graph_id) // verifier 1 push signature
        .await;
    config.client_1.flush().await;

    config.client_0.sync().await;
    config
        .client_0
        .process_peg_in_as_verifier(&peg_in_graph_id) // broadcast peg-in confirm
        .await;

    let peg_in_graph = find_peg_in_graph_by_peg_out(&config.client_0, &peg_out_graph_id).unwrap();
    let peg_in_confirm_tx = peg_in_graph.peg_in_confirm_transaction_ref().tx();
    let peg_in_confirm_vout: usize = 0;
    let peg_in_confirm_amount = peg_in_confirm_tx.output[peg_in_confirm_vout].value;

    let mock_adaptor_config = MockAdaptorConfig {
        peg_out_init_events: Some(vec![PegOutEvent {
            source_outpoint: OutPoint {
                txid: peg_in_graph.peg_in_confirm_transaction.tx().compute_txid(),
                vout: peg_in_confirm_vout.to_u32().unwrap(),
            },
            amount: peg_in_confirm_amount,
            timestamp: 1722328130u32,
            withdrawer_chain_address: config.withdrawer_evm_address,
            withdrawer_destination_address: generate_p2pkh_address(
                config.withdrawer_context.network,
                &config.withdrawer_context.withdrawer_public_key,
            )
            .to_string(),
            withdrawer_public_key_hash: config
                .withdrawer_context
                .withdrawer_public_key
                .pubkey_hash(),
            operator_public_key: config.operator_context.operator_public_key,
            tx_hash: [0u8; 32].into(), // 32 bytes 0
        }]),
        peg_out_burnt_events: None,
        peg_out_minted_events: None,
    };
    let adaptor = MockAdaptor::new(Some(mock_adaptor_config));
    let chain_service = Chain::new(Box::new(adaptor));

    config.client_0.set_chain_service(chain_service);
    config.client_0.sync_l2().await;

    let peg_out_graph = get_peg_out_graph_mut(&mut config.client_0, peg_out_graph_id.clone());
    let peg_out_tx = peg_out_graph
        .peg_out(
            &esplora_client,
            &config.operator_context,
            Input {
                outpoint: peg_out_outpoint,
                amount: peg_out_amount,
            },
        )
        .await
        .unwrap();
    check_tx_output_sum(ONE_HUNDRED, &peg_out_tx);
    let peg_out_result = esplora_client.broadcast(&peg_out_tx).await;
    wait_for_confirmation(config.network).await;
    println!("peg out tx result: {:?}\n", peg_out_result);
    assert!(peg_out_result.is_ok());

    let peg_out_confirm_tx = peg_out_graph
        .peg_out_confirm(&esplora_client)
        .await
        .unwrap();
    check_tx_output_sum(
        reward_amount + PEG_OUT_FEE - MIN_RELAY_FEE_PEG_OUT_CONFIRM,
        &peg_out_confirm_tx,
    );
    let peg_out_confirm_result = esplora_client.broadcast(&peg_out_confirm_tx).await;
    wait_for_confirmation(config.network).await;
    println!("peg out confirm tx result: {:?}\n", peg_out_confirm_result);
    assert!(peg_out_confirm_result.is_ok());

    let private_data = config.client_0.private_data();
    let secrets_map = private_data.commitment_secrets[&config.operator_context.operator_public_key]
        [&peg_out_graph_id]
        .clone();
    let peg_out_graph = get_peg_out_graph_mut(&mut config.client_0, peg_out_graph_id.clone());
    let kick_off_1_tx = peg_out_graph
        .kick_off_1(
            &esplora_client,
            &config.operator_context,
            &secrets_map[&CommitmentMessageId::PegOutTxIdSourceNetwork],
            &secrets_map[&CommitmentMessageId::PegOutTxIdDestinationNetwork],
        )
        .await
        .unwrap();
    check_tx_output_sum(
        reward_amount + PEG_OUT_FEE - MIN_RELAY_FEE_PEG_OUT_CONFIRM - MIN_RELAY_FEE_KICK_OFF_1,
        &kick_off_1_tx,
    );
    let kick_off_1_result = esplora_client.broadcast(&kick_off_1_tx).await;
    wait_for_confirmation(config.network).await;
    println!(
        "kick off 1 tx result: {:?}, {:?}\n",
        kick_off_1_result,
        kick_off_1_tx.compute_txid()
    );
    assert!(kick_off_1_result.is_ok());

    let start_time_tx = peg_out_graph
        .start_time(
            &esplora_client,
            &config.operator_context,
            &secrets_map[&CommitmentMessageId::StartTime],
        )
        .await
        .unwrap();
    check_tx_output_sum(DUST_AMOUNT, &start_time_tx);

    wait_for_timelock_expiry(config.network, Some("kick off 1 connector 1")).await;
    let start_time_timeout_tx = peg_out_graph
        .start_time_timeout(
            &esplora_client,
            generate_pay_to_pubkey_script(&config.depositor_context.depositor_public_key),
        )
        .await
        .unwrap();
    check_tx_output_sum(
        reward_amount + PEG_OUT_FEE
            - MIN_RELAY_FEE_PEG_OUT_CONFIRM
            - MIN_RELAY_FEE_KICK_OFF_1
            - MIN_RELAY_FEE_START_TIME_TIMEOUT
            - DUST_AMOUNT,
        &start_time_timeout_tx,
    );

    println!("Funding crowdfunding input ...");
    let challenge_input_amount = Amount::from_sat(peg_out_graph.min_crowdfunding_amount() + 1);
    let challenge_funding_utxo_address = generate_pay_to_pubkey_script_address(
        config.network,
        &config.depositor_context.depositor_public_key,
    );
    faucet
        .fund_input(&challenge_funding_utxo_address, challenge_input_amount)
        .await
        .wait()
        .await;

    let challenge_funding_outpoint = generate_stub_outpoint(
        &config.client_0,
        &challenge_funding_utxo_address,
        challenge_input_amount,
    )
    .await;
    let depositor_pubkey_script =
        generate_pay_to_pubkey_script(&config.depositor_context.depositor_public_key);
    let challenge_crowdfunding_inputs = vec![InputWithScript {
        outpoint: challenge_funding_outpoint,
        amount: challenge_input_amount,
        script: &depositor_pubkey_script,
    }];

    let peg_out_graph = get_peg_out_graph_mut(&mut config.client_0, peg_out_graph_id.clone());
    let challenge_tx = peg_out_graph
        .challenge(
            &esplora_client,
            &challenge_crowdfunding_inputs,
            &config.depositor_context.depositor_keypair,
            depositor_pubkey_script.clone(),
        )
        .await
        .unwrap();
    // crowdfunding discrepency less than dust will be lost as relay fee
    check_tx_output_sum(
        challenge_input_amount.to_sat() - 1 + DUST_AMOUNT - MIN_RELAY_FEE_CHALLENGE,
        &challenge_tx,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    let kick_off_timeout_tx = peg_out_graph
        .kick_off_timeout(&esplora_client, reward_address.script_pubkey())
        .await
        .unwrap();
    check_tx_output_sum(
        reward_amount + PEG_OUT_FEE
            - MIN_RELAY_FEE_PEG_OUT_CONFIRM
            - MIN_RELAY_FEE_KICK_OFF_1
            - MIN_RELAY_FEE_KICK_OFF_TIMEOUT
            - DUST_AMOUNT * 2
            - MIN_RELAY_FEE_START_TIME,
        &kick_off_timeout_tx,
    );

    let kick_off_2_tx = peg_out_graph
        .kick_off_2(
            &esplora_client,
            &config.operator_context,
            &config.commitment_secrets[&CommitmentMessageId::Superblock],
            &config.commitment_secrets[&CommitmentMessageId::SuperblockHash],
        )
        .await
        .unwrap();
    check_tx_output_sum(
        reward_amount + PEG_OUT_FEE
            - MIN_RELAY_FEE_PEG_OUT_CONFIRM
            - MIN_RELAY_FEE_KICK_OFF_1
            - MIN_RELAY_FEE_KICK_OFF_2
            - DUST_AMOUNT * 2
            - MIN_RELAY_FEE_START_TIME,
        &kick_off_2_tx,
    );
    let kick_off_2_result = esplora_client.broadcast(&kick_off_2_tx).await;
    println!(
        "kick off 2 tx result: {:?}, {:?}\n",
        kick_off_2_result,
        kick_off_2_tx.compute_txid()
    );
    wait_for_confirmation(config.network).await;
    wait_for_timelock_expiry(config.network, Some("kick off 2 connector 3")).await;

    let take_1_tx = peg_out_graph.take_1(&esplora_client).await.unwrap();
    // minus 1 dust from kick off 1 connector 2
    check_tx_output_sum(
        INITIAL_AMOUNT + reward_amount + MIN_RELAY_FEE_ASSERT_SET - MIN_RELAY_FEE_TAKE_1
            + MIN_RELAY_FEE_DISPROVE
            - DUST_AMOUNT,
        &take_1_tx,
    );

    let verifier_pubkey_script =
        generate_pay_to_pubkey_script(&config.verifier_0_context.verifier_public_key);
    let disprove_chain_tx = peg_out_graph
        .disprove_chain(&esplora_client, verifier_pubkey_script.clone())
        .await
        .unwrap();
    // minus 2 dust from kick off 1, 1 dust from kick off 2
    check_tx_output_sum(
        reward_amount + MIN_RELAY_FEE_ASSERT_SET - MIN_RELAY_FEE_DISPROVE_CHAIN
            + MIN_RELAY_FEE_DISPROVE
            - DUST_AMOUNT * 3,
        &disprove_chain_tx,
    );

    let assert_initial_tx = peg_out_graph.assert_initial(&esplora_client).await.unwrap();
    // minus 2 dust from kick off 1, 1 dust from kick off 2
    check_tx_output_sum(
        reward_amount + MIN_RELAY_FEE_ASSERT_SET - MIN_RELAY_FEE_ASSERT_INITIAL
            + MIN_RELAY_FEE_DISPROVE
            - DUST_AMOUNT * 3,
        &assert_initial_tx,
    );
    let assert_initial_result = esplora_client.broadcast(&assert_initial_tx).await;
    println!(
        "assert initial tx result: {:?}, {:?}\n",
        assert_initial_result,
        assert_initial_tx.compute_txid()
    );
    wait_for_confirmation(config.network).await;

    let assert_commit1_tx = peg_out_graph
        .assert_commit_1(
            &esplora_client,
            &config.commitment_secrets,
            &config.invalid_proof,
        )
        .await
        .unwrap();
    // checked in assert_commit_1 single tx test
    // check_tx_output_sum(assert_commit1_dust_amount, &assert_commit1_tx);
    let assert_commit1_result = esplora_client.broadcast(&assert_commit1_tx).await;
    println!(
        "assert commit 1 tx result: {:?}, {:?}\n",
        assert_commit1_result,
        assert_commit1_tx.compute_txid()
    );
    wait_for_confirmation(config.network).await;

    let assert_commit2_tx = peg_out_graph
        .assert_commit_2(
            &esplora_client,
            &config.commitment_secrets,
            &config.invalid_proof,
        )
        .await
        .unwrap();
    // checked in assert_commit_2 single tx test
    // check_tx_output_sum(assert_commit2_dust_amount, &assert_commit2_tx);
    let assert_commit2_result = esplora_client.broadcast(&assert_commit2_tx).await;
    println!(
        "assert commit 2 tx result: {:?}, {:?}\n",
        assert_commit2_result,
        assert_commit2_tx.compute_txid()
    );
    wait_for_confirmation(config.network).await;

    let assert_final_tx = peg_out_graph.assert_final(&esplora_client).await.unwrap();
    // minus 2 dust from kick off 1, 1 dust from kick off 2
    check_tx_output_sum(
        reward_amount + MIN_RELAY_FEE_DISPROVE - DUST_AMOUNT * 3,
        &assert_final_tx,
    );
    let assert_final_result = esplora_client.broadcast(&assert_final_tx).await;
    println!(
        "assert final tx result: {:?}, {:?}\n",
        assert_final_result,
        assert_final_tx.compute_txid()
    );
    wait_for_confirmation(config.network).await;
    wait_for_timelock_expiry(config.network, Some("assert final connector 4")).await;

    let take_2_tx = peg_out_graph
        .take_2(&esplora_client, &config.operator_context)
        .await
        .unwrap();
    // minus 2 dust from kick off 1, 1 dust from kick off 2
    check_tx_output_sum(
        INITIAL_AMOUNT + reward_amount + MIN_RELAY_FEE_DISPROVE
            - MIN_RELAY_FEE_TAKE_2
            - DUST_AMOUNT * 3,
        &take_2_tx,
    );

    let zk_verifying_key = config.invalid_proof.vk;
    let disprove_tx = peg_out_graph
        .disprove(
            &esplora_client,
            verifier_pubkey_script.clone(),
            &zk_verifying_key,
        )
        .await
        .unwrap();
    // minus 2 dust from kick off 1, 1 dust from kick off 2, 1 dust from assert final
    check_tx_output_sum(reward_amount - DUST_AMOUNT * 4, &disprove_tx);
}

// TODO: consider making the graph getter in client public after refactor
fn get_peg_in_graph_mut(client: &mut BitVMClient, id: String) -> &mut PegInGraph {
    client
        .data_mut()
        .peg_in_graphs
        .iter_mut()
        .find(|graph| graph.id().eq(&id))
        .unwrap()
}

// TODO: consider making the graph getter in client public after refactor
fn get_peg_out_graph_mut(client: &mut BitVMClient, id: String) -> &mut PegOutGraph {
    client
        .data_mut()
        .peg_out_graphs
        .iter_mut()
        .find(|graph| graph.id().eq(&id))
        .unwrap()
}
