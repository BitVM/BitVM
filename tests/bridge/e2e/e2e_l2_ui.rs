use futures::StreamExt;
use std::time::Duration;

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{find_peg_out_graph, generate_stub_outpoint, TX_WAIT_TIME},
    setup::setup_test,
};
use bitcoin::{Address, Amount};
use bitvm::bridge::{client::chain::chain::Chain, transactions::pre_signed::PreSignedTransaction};
use bitvm::bridge::{
    client::client::BitVMClient,
    contexts::{depositor::DepositorContext, operator::OperatorContext},
    graphs::{
        base::{BaseGraph, FEE_AMOUNT, INITIAL_AMOUNT},
        peg_out::PegOutOperatorStatus,
    },
    scripts::generate_pay_to_pubkey_script_address,
    transactions::base::Input,
};
use esplora_client::Builder;
use serial_test::serial;
use tokio::time::sleep;

#[ignore]
#[tokio::test]
#[serial]
async fn test_e2e_0_simulate_complete_peg_in() {
    println!("Simulate peg in ...");
    let (mut operator_client, _, peg_out_graph_id, _, _) = create_graph().await;
    operator_client.sync().await;
    operator_client.sync_l2().await;

    let esplora = Builder::new("http://localhost:8094/regtest/api/")
        .build_async()
        .expect("Could not build esplora client");
    let peg_out_graph = find_peg_out_graph(&operator_client, peg_out_graph_id.as_str()).unwrap();
    let status = peg_out_graph.operator_status(&esplora).await;
    println!(">>>>> Graph id: {} status: {}", peg_out_graph.id(), status);
    println!("Peg in completed, please proceed to initate peg out in UI.");
}

#[ignore]
#[tokio::test]
#[serial]
async fn test_e2e_1_simulate_peg_out() {
    let config = setup_test().await;
    let esplora = Builder::new("http://localhost:8094/regtest/api/")
        .build_async()
        .expect("Could not build esplora client");

    let mut operator_client = config.client_0;
    operator_client.sync().await;
    operator_client.sync_l2().await;

    println!("Using first found PegOutStartPegOut graph ...");
    let peg_out_graphs = &operator_client.get_data().peg_out_graphs.clone();
    let peg_out_graph_result = futures::stream::iter(peg_out_graphs)
        .filter(|g| {
            Box::pin(async {
                let status = g.operator_status(&esplora).await;
                println!(">>>>> Graph id: {} status: {}", g.id(), status);
                match status {
                    PegOutOperatorStatus::PegOutStartPegOut => true,
                    _ => false,
                }
            })
        })
        .next()
        .await;

    let peg_out_graph = match peg_out_graph_result {
        Some(peg_out_graph) => peg_out_graph,
        None => panic!("No PegOutStartPegOut graph found"),
    };
    let peg_out_chain_event = match &peg_out_graph.peg_out_chain_event {
        Some(peg_out_chain_event) => peg_out_chain_event,
        None => panic!("Fatal! No peg_out_chain_event found"),
    };

    let operator_funding_utxo_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );
    println!(
        "operator_funding_utxo_address: {:?}",
        operator_funding_utxo_address
    );
    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    faucet
        .fund_input(&operator_funding_utxo_address, peg_out_chain_event.amount)
        .await
        .wait()
        .await;
    let operator_funding_outpoint = generate_stub_outpoint(
        &operator_client,
        &operator_funding_utxo_address,
        peg_out_chain_event.amount,
    )
    .await;
    println!(
        "operator_funding_utxo.txid: {:?}",
        operator_funding_outpoint.txid
    );
    let input = Input {
        outpoint: operator_funding_outpoint,
        amount: peg_out_chain_event.amount,
    };
    eprintln!("Broadcasting peg out...");
    operator_client
        .broadcast_peg_out(&peg_out_graph.id(), input)
        .await;

    // Wait for peg-out transaction to be mined
    println!("Waiting for peg-out tx...");
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;

    operator_client.flush().await;

    let synced_peg_out_graph = find_peg_out_graph(&operator_client, peg_out_graph.id()).unwrap();
    let peg_out_txid = synced_peg_out_graph
        .peg_out_transaction
        .as_ref()
        .unwrap()
        .tx()
        .compute_txid();
    println!(
        "Peg out tx [{}] broadcasted, please proceed to burnEBTC in L2.",
        peg_out_txid
    );
}

#[ignore]
#[tokio::test]
#[serial]
async fn test_e2e_2_verify_burn_event_and_simulate_peg_out_process() {
    let chain_adaptor = Chain::new();
    let burnt_events = chain_adaptor.get_peg_out_burnt().await;
    assert!(burnt_events.is_ok());
    let burnt_events = burnt_events.unwrap();
    assert!(burnt_events.len() > 0);

    let burnt_event = burnt_events.iter().next().unwrap();
    println!("First burnt event fetched: {:?}", burnt_event);

    //TODO: broadcast_transactions_from_peg_out_graph
}

//TODO: refactor with test_musig2_peg_out
async fn create_graph() -> (
    BitVMClient,
    BitVMClient,
    String,
    DepositorContext,
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

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    faucet
        .fund_inputs(&depositor_operator_verifier_0_client, &funding_inputs)
        .await;
    println!("Waiting for funding inputs tx...");
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;

    let kick_off_outpoint = generate_stub_outpoint(
        &depositor_operator_verifier_0_client,
        &kick_off_funding_utxo_address,
        kick_off_input_amount,
    )
    .await;

    dotenv::dotenv().ok();
    let env_user0_evm_address = dotenv::var("BRIDGE_USER_0_EVM_ADDRESS");
    let depositor_evm_address = match env_user0_evm_address {
        Ok(depositor_evm_address) => depositor_evm_address,
        Err(_) => config.depositor_evm_address,
    };
    eprintln!("Creating peg-in graph...");
    // create and complete peg-in graph
    let peg_in_graph_id = create_peg_in_graph(
        &mut depositor_operator_verifier_0_client,
        &mut verifier_1_client,
        deposit_funding_address,
        deposit_input_amount,
        &depositor_evm_address,
    )
    .await;

    depositor_operator_verifier_0_client.sync().await;
    eprintln!("Creating peg-out graph...");
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
    depositor_operator_verifier_0_client.push_verifier_nonces(&peg_out_graph_id);
    depositor_operator_verifier_0_client.flush().await;

    eprintln!("Verifier 1 push peg-out nonces");
    verifier_1_client.sync().await;
    verifier_1_client.push_verifier_nonces(&peg_out_graph_id);
    verifier_1_client.flush().await;

    eprintln!("Verifier 0 pre-sign peg-out");
    depositor_operator_verifier_0_client.sync().await;
    depositor_operator_verifier_0_client.push_verifier_signature(&peg_out_graph_id);
    depositor_operator_verifier_0_client.flush().await;

    eprintln!("Verifier 1 pre-sign peg-out");
    verifier_1_client.sync().await;
    verifier_1_client.push_verifier_signature(&peg_out_graph_id);
    verifier_1_client.flush().await;

    return (
        depositor_operator_verifier_0_client,
        verifier_1_client,
        peg_out_graph_id,
        config.depositor_context,
        config.operator_context,
    );
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
    client_0.push_verifier_nonces(&graph_id);
    client_0.flush().await;

    client_1.sync().await;
    client_1.push_verifier_nonces(&graph_id);
    client_1.flush().await;

    client_0.sync().await;
    client_0.push_verifier_signature(&graph_id);
    client_0.flush().await;

    client_1.sync().await;
    client_1.push_verifier_signature(&graph_id);
    client_1.flush().await;

    // Wait for peg-in deposit transaction to be mined
    println!("Waiting for peg-in deposit tx...");
    sleep(Duration::from_secs(TX_WAIT_TIME)).await;

    client_0.sync().await;
    client_0.broadcast_peg_in_confirm(&graph_id).await;
    client_0.flush().await;

    return graph_id;
}

// async fn broadcast_transactions_from_peg_out_graph(
//     client: &mut BitVMClient,
//     peg_out_graph_id: &String,
//     depositor_context: &DepositorContext,
//     with_kick_off_2_tx: bool,
//     with_challenge_tx: bool,
//     with_assert_tx: bool,
// ) {
//     eprintln!("Broadcasting kick-off 1...");
//     client.sync().await;
//     client.broadcast_kick_off_1(&peg_out_graph_id).await;

//     // Wait for peg-in deposit transaction to be mined
//     println!("Waiting for peg-out kick-off tx...");
//     sleep(Duration::from_secs(TX_WAIT_TIME)).await;

//     if with_kick_off_2_tx {
//         eprintln!("Broadcasting start time...");
//         client.broadcast_start_time(&peg_out_graph_id).await;

//         println!("Waiting for peg-out start time tx...");
//         sleep(Duration::from_secs(TX_WAIT_TIME)).await;

//         eprintln!("Broadcasting kick-off 2...");
//         client.broadcast_kick_off_2(&peg_out_graph_id).await;

//         println!("Waiting for peg-out kick-off 2 tx...");
//         sleep(Duration::from_secs(TX_WAIT_TIME)).await;
//     }

//     if with_challenge_tx {
//         let challenge_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
//         let challenge_funding_utxo_address = generate_pay_to_pubkey_script_address(
//             depositor_context.network,
//             &depositor_context.depositor_public_key,
//         );
//         let faucet = Faucet::new(FaucetType::EsploraRegtest);
//         faucet
//             .fund_input_and_wait(&challenge_funding_utxo_address, challenge_input_amount)
//             .await;

//         let challenge_funding_outpoint = generate_stub_outpoint(
//             &client,
//             &challenge_funding_utxo_address,
//             challenge_input_amount,
//         )
//         .await;
//         let challenge_crowdfunding_input = InputWithScript {
//             outpoint: challenge_funding_outpoint,
//             amount: challenge_input_amount,
//             script: &generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
//         };
//         eprintln!("Broadcasting challenge...");
//         client
//             .broadcast_challenge(
//                 &peg_out_graph_id,
//                 &vec![challenge_crowdfunding_input],
//                 generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
//             )
//             .await;

//         println!("Waiting for peg-out challenge tx...");
//         sleep(Duration::from_secs(TX_WAIT_TIME)).await;
//     }

//     if with_assert_tx {
//         eprintln!("Broadcasting assert...");
//         client.broadcast_assert(&peg_out_graph_id).await;

//         println!("Waiting for peg-out assert tx...");
//         sleep(Duration::from_secs(TX_WAIT_TIME)).await;
//     }
// }
