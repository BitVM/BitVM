use bitcoin::Amount;

use bitvm::bridge::{
    graphs::base::DUST_AMOUNT,
    transactions::base::{
        MIN_RELAY_FEE_ASSERT_COMMIT1, MIN_RELAY_FEE_ASSERT_COMMIT2, MIN_RELAY_FEE_ASSERT_FINAL,
        MIN_RELAY_FEE_ASSERT_INITIAL,
    },
};

use crate::bridge::{
    assert::helper::create_and_mine_assert_initial_tx,
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, get_reward_amount},
    setup::{setup_test_full, ONE_HUNDRED},
};

#[tokio::test]
async fn test_assert_initial_tx_success() {
    let config = setup_test_full().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let reward_amount = get_reward_amount(ONE_HUNDRED);
    let total_dust_amount = (config.assert_commit_connectors_e_1.connectors_num()
        + config.assert_commit_connectors_e_2.connectors_num()) as u64
        * DUST_AMOUNT;
    let amount = Amount::from_sat(
        reward_amount
            + total_dust_amount
            + MIN_RELAY_FEE_ASSERT_INITIAL
            + MIN_RELAY_FEE_ASSERT_COMMIT1
            + MIN_RELAY_FEE_ASSERT_COMMIT2
            + MIN_RELAY_FEE_ASSERT_FINAL,
    );
    let tx = create_and_mine_assert_initial_tx(&config, &faucet, amount).await;
    check_tx_output_sum(
        reward_amount
            + total_dust_amount
            + MIN_RELAY_FEE_ASSERT_COMMIT1
            + MIN_RELAY_FEE_ASSERT_COMMIT2
            + MIN_RELAY_FEE_ASSERT_FINAL,
        &tx,
    );
}
