use bitcoin::Amount;

use bitvm::bridge::{
    commitments::CommitmentMessageId,
    connectors::base::TaprootConnector,
    graphs::base::DUST_AMOUNT,
    superblock::get_start_time_block_number,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_START_TIME},
        start_time::StartTimeTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::check_tx_output_sum,
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_start_time_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let input_value0 = Amount::from_sat(DUST_AMOUNT + MIN_RELAY_FEE_START_TIME);
    let funding_utxo_address0 = config.connector_2.generate_taproot_address();
    faucet
        .fund_input(&funding_utxo_address0, input_value0)
        .await
        .wait()
        .await;
    let funding_outpoint0 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address0, input_value0).await;

    let mut start_time_tx = StartTimeTransaction::new(
        &config.operator_context,
        &config.connector_2,
        Input {
            outpoint: funding_outpoint0,
            amount: input_value0,
        },
    );

    start_time_tx.sign(
        &config.operator_context,
        &config.connector_2,
        get_start_time_block_number(config.network),
        &config.commitment_secrets[&CommitmentMessageId::StartTime],
    );

    let tx = start_time_tx.finalize();
    check_tx_output_sum(DUST_AMOUNT, &tx);
    // TODO: revisit here after superblock time lock is implemented
    // wait_timelock_expiry(config.network, Some("start time absolute lock time")).await;
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Start time tx result: {:?}\n", result);
    assert!(result.is_ok());
}
