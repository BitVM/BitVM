use bridge::error::{ChunkerError, Error};

use colored::Colorize;
use serial_test::serial;

use super::utils::{broadcast_txs_for_disprove_scenario, create_peg_out_graph};

#[tokio::test]
#[serial(client)]
async fn test_e2e_disprove_reject() {
    let (
        mut verifier_0_operator_depositor,
        mut verifier_1,
        peg_out_graph_id,
        reward_script,
        peg_out_input,
        valid_proof,
        _,
    ) = create_peg_out_graph().await;

    broadcast_txs_for_disprove_scenario(
        &mut verifier_0_operator_depositor,
        &mut verifier_1,
        &peg_out_graph_id,
        peg_out_input,
        &valid_proof,
    )
    .await;

    let result = verifier_1
        .broadcast_disprove(&peg_out_graph_id, reward_script)
        .await;

    assert!(
        matches!(result, Err(Error::Chunker(ChunkerError::ValidProof))),
        "{}",
        &format!(
            "Should have failed with {} but got {:?}",
            Error::Chunker(ChunkerError::ValidProof),
            result
        )
        .bold()
        .red(),
    );

    println!(
        "{}",
        "Successfully rejected disproving correct ZK proof"
            .bold()
            .green()
    );
}
