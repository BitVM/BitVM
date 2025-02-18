use colored::Colorize;
use serial_test::serial;

use super::utils::{broadcast_txs_for_disprove_scenario, create_peg_out_graph};

#[tokio::test]
#[serial(client)]
async fn test_e2e_disprove_success() {
    let (
        mut verifier_0_operator_depositor,
        mut verifier_1,
        peg_out_graph_id,
        reward_script,
        peg_out_input,
        _,
        invalid_proof,
    ) = create_peg_out_graph().await;

    broadcast_txs_for_disprove_scenario(
        &mut verifier_0_operator_depositor,
        &mut verifier_1,
        &peg_out_graph_id,
        peg_out_input,
        &invalid_proof,
    )
    .await;

    let result = verifier_1
        .broadcast_disprove(&peg_out_graph_id, reward_script)
        .await;

    assert!(
        result.is_ok(),
        "{}: {}",
        "Failed to disprove incorrect ZK proof".bold().red(),
        result.unwrap_err()
    );

    println!(
        "{}",
        "Succesfully disproved incorrect ZK proof".bold().green()
    );
}
