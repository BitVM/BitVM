use std::time::Duration;

use bitcoin::Amount;

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::base::Input,
};

use tokio::time::sleep;

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_musig2_peg_in() {
    let (
        mut depositor_operator_verifier_0_client,
        mut verifier_1_client,
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
        depositor_evm_address,
        _,
    ) = setup_test().await;

    // Depositor: generate graph
    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let outpoint = generate_stub_outpoint(
        &depositor_operator_verifier_0_client,
        &generate_pay_to_pubkey_script_address(
            depositor_context.network,
            &depositor_context.depositor_public_key,
        ),
        amount,
    )
    .await;

    let graph_id = depositor_operator_verifier_0_client
        .create_peg_in_graph(Input { outpoint, amount }, &depositor_evm_address)
        .await;
    println!("Depositor: Created new graph {graph_id}");

    println!("Depositor: Mining peg in deposit...");
    depositor_operator_verifier_0_client
        .broadcast_peg_in_deposit(&graph_id)
        .await;

    println!("Depositor: Saving state changes to remote...");
    depositor_operator_verifier_0_client.flush().await;

    // Verifier 0: push nonces
    println!("Verifier 0: Reading state from remote...");
    depositor_operator_verifier_0_client.sync().await;

    println!("Verifier 0: Generating nonces...");
    depositor_operator_verifier_0_client.push_peg_in_nonces(&graph_id);

    println!("Verifier 0: Saving state changes to remote...");
    depositor_operator_verifier_0_client.flush().await;

    // Verifier 1: push nonces
    println!("Verifier 1: Reading state from remote...");
    verifier_1_client.sync().await;

    println!("Verifier 1: Generating nonces...");
    verifier_1_client.push_peg_in_nonces(&graph_id);

    println!("Verifier 1: Saving state changes to remote...");
    verifier_1_client.flush().await;

    // Verifier 0: presign
    println!("Verifier 0: Reading state from remote...");
    depositor_operator_verifier_0_client.sync().await;

    println!("Verifier 0: Pre-signing...");
    depositor_operator_verifier_0_client.pre_sign_peg_in(&graph_id);

    println!("Verifier 0: Saving state changes to remote...");
    depositor_operator_verifier_0_client.flush().await;

    // Verifier 1: presign
    println!("Verifier 1: Reading state from remote...");
    verifier_1_client.sync().await;

    println!("Verifier 1: Pre-signing...");
    verifier_1_client.pre_sign_peg_in(&graph_id);

    println!("Verifier 1: Saving state changes to remote...");
    verifier_1_client.flush().await;

    // Operator: finalize & verify
    println!("Operator: Reading state from remote...");
    depositor_operator_verifier_0_client.sync().await;

    let wait_time = 45;
    println!("Waiting {wait_time}s for peg-in deposit transaction to be mined...");
    sleep(Duration::from_secs(wait_time)).await; // TODO: Replace this with a 'wait x amount of time till tx is mined' routine.
                                                 // See the relevant TODO in PegInGraph::confirm().

    println!("Depositor: Mining peg in confirm...");
    depositor_operator_verifier_0_client
        .broadcast_peg_in_confirm(&graph_id)
        .await;

    println!("Operator: Saving state changes to remote...");
    depositor_operator_verifier_0_client.flush().await;
}
