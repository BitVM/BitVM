use std::time::Duration;

use bitcoin::{Address, Amount};
use bitvm::bridge::{
    client::client::BitVMClient,
    contexts::{
        depositor::DepositorContext, operator::OperatorContext, withdrawer::WithdrawerContext,
    },
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::base::Input,
};
use serial_test::serial;
use tokio::time::sleep;

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{generate_stub_outpoint, TX_WAIT_TIME},
    setup::setup_test,
};

#[ignore]
#[tokio::test]
#[serial]
async fn test_e2e_simulate_complete_peg_in() {
    let (mut operator_client, _, _, _, _, _, _) = create_graph().await;
    operator_client.sync().await;
    println!("Sync L2");
    operator_client.sync_l2().await;
}

async fn create_graph() -> (
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

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
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

    return (
        depositor_operator_verifier_0_client,
        verifier_1_client,
        peg_out_graph_id,
        config.depositor_context,
        config.withdrawer_evm_address,
        config.withdrawer_context,
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

    return graph_id;
}
