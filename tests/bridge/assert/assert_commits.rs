use bitcoin::{Amount, OutPoint};

use bitvm::{
    bridge::{
        graphs::base::DUST_AMOUNT,
        transactions::{
            assert_transactions::{
                assert_commit_1::AssertCommit1Transaction,
                assert_commit_2::AssertCommit2Transaction,
                utils::sign_assert_tx_with_groth16_proof,
            },
            base::{
                BaseTransaction, Input, MIN_RELAY_FEE_ASSERT_COMMIT1, MIN_RELAY_FEE_ASSERT_COMMIT2,
                MIN_RELAY_FEE_ASSERT_FINAL, MIN_RELAY_FEE_ASSERT_INITIAL,
            },
        },
    },
    chunker::disprove_execution::RawProof,
};
use num_traits::ToPrimitive;

use crate::bridge::{
    assert::helper::create_and_mine_assert_initial_tx,
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, get_reward_amount, wait_timelock_expiry},
    setup::{setup_test_full, ONE_HUNDRED},
};

#[tokio::test]
async fn test_assert_commits_tx_success() {
    let config = setup_test_full().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let reward_amount = get_reward_amount(ONE_HUNDRED);
    let assert_commit1_dust_amount =
        config.assert_commit_connectors_e_1.connectors_num() as u64 * DUST_AMOUNT;
    let assert_commit2_dust_amount =
        config.assert_commit_connectors_e_2.connectors_num() as u64 * DUST_AMOUNT;
    let amount = Amount::from_sat(
        reward_amount
            + assert_commit1_dust_amount
            + assert_commit2_dust_amount
            + MIN_RELAY_FEE_ASSERT_INITIAL
            + MIN_RELAY_FEE_ASSERT_COMMIT1
            + MIN_RELAY_FEE_ASSERT_COMMIT2
            + MIN_RELAY_FEE_ASSERT_FINAL,
    );
    let assert_inital_tx = create_and_mine_assert_initial_tx(&config, &faucet, amount).await;

    let mut vout_base = 1;
    let mut assert_commit1 = AssertCommit1Transaction::new(
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_f.connector_f_1,
        (0..config.assert_commit_connectors_e_1.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint {
                    txid: assert_inital_tx.compute_txid(),
                    vout: (idx + vout_base).to_u32().unwrap(),
                },
                amount: assert_inital_tx.output[idx + vout_base].value,
            })
            .collect(),
    );

    vout_base += config.assert_commit_connectors_e_1.connectors_num();

    let mut assert_commit2 = AssertCommit2Transaction::new(
        &config.assert_commit_connectors_e_2,
        &config.assert_commit_connectors_f.connector_f_2,
        (0..config.assert_commit_connectors_e_2.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint {
                    txid: assert_inital_tx.compute_txid(),
                    vout: (idx + vout_base).to_u32().unwrap(),
                },
                amount: assert_inital_tx.output[idx + vout_base].value,
            })
            .collect(),
    );

    let (witness_for_commit1, witness_for_commit2) =
        sign_assert_tx_with_groth16_proof(&config.commitment_secrets, &RawProof::default());
    assert_commit1.sign(
        &config.assert_commit_connectors_e_1,
        witness_for_commit1.clone(),
    );
    assert_commit2.sign(
        &config.assert_commit_connectors_e_2,
        witness_for_commit2.clone(),
    );

    let assert_commit1_tx = assert_commit1.finalize();
    let assert_commit2_tx = assert_commit2.finalize();
    check_tx_output_sum(assert_commit1_dust_amount, &assert_commit1_tx);
    check_tx_output_sum(assert_commit2_dust_amount, &assert_commit2_tx);
    // println!(
    //     ">>>>>> MINE ASSERT COMMIT 1 input amount: {:?}, virtual size: {:?}, outputs: {:?}",
    //     DUST_AMOUNT * config.assert_commit_connectors_e_1.connectors_num() as u64 + 10000000,
    //     assert_commit1_tx.vsize(),
    //     assert_commit1_tx
    //         .output
    //         .iter()
    //         .map(|o| o.value.to_sat())
    //         .collect::<Vec<u64>>(),
    // );
    // println!(
    //     ">>>>>> ASSERT COMMIT 1 TX OUTPUTS SIZE: {:?}",
    //     assert_commit1_tx
    //         .output
    //         .iter()
    //         .map(|o| o.size())
    //         .collect::<Vec<usize>>()
    // );

    // println!(
    //     ">>>>>> MINE ASSERT COMMIT 2 input amount: {:?}, virtual size: {:?}, outputs: {:?}",
    //     DUST_AMOUNT * config.assert_commit_connectors_e_2.connectors_num() as u64 + 10000000,
    //     assert_commit2_tx.vsize(),
    //     assert_commit2_tx
    //         .output
    //         .iter()
    //         .map(|o| o.value.to_sat())
    //         .collect::<Vec<u64>>(),
    // );
    // println!(
    //     ">>>>>> ASSERT COMMIT 2 TX OUTPUTS SIZE: {:?}",
    //     assert_commit2_tx
    //         .output
    //         .iter()
    //         .map(|o| o.size())
    //         .collect::<Vec<usize>>()
    // );

    // println!("Transaction hex: \n{}", serialize_hex(&assert_commit1_tx));
    // println!("Transaction hex: \n{}", serialize_hex(&assert_commit2_tx));
    // println!("Assert commit 1 total size: {}, virtual size: {}", assert_commit1_tx.total_size(), assert_commit1_tx.vsize());
    // println!("Assert commit 2 total size: {}, virtual size: {}", assert_commit2_tx.total_size(), assert_commit2_tx.vsize());

    wait_timelock_expiry(config.network, Some("assert initial connector 4")).await;

    let commit1_result = config.client_0.esplora.broadcast(&assert_commit1_tx).await;
    println!("Txid: {:?}", assert_commit1_tx.compute_txid());
    println!("Assert commit 1 tx result: {:?}\n", commit1_result);
    assert!(commit1_result.is_ok());

    let commit2_result = config.client_0.esplora.broadcast(&assert_commit2_tx).await;
    println!("Txid: {:?}", assert_commit2_tx.compute_txid());
    println!("Assert commit 2 tx result: {:?}\n", commit2_result);
    assert!(commit2_result.is_ok());
}
