use bitcoin::{Address, Amount, OutPoint};
use bridge::{
    commitments::CommitmentMessageId,
    connectors::base::TaprootConnector,
    graphs::base::DUST_AMOUNT,
    superblock::get_start_time_block_number,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_KICK_OFF_1, MIN_RELAY_FEE_START_TIME},
        start_time::StartTimeTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, verify_funding_inputs, wait_timelock_expiry},
    integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_start_time_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_1_input_amount = Amount::from_sat(
        INITIAL_AMOUNT + MIN_RELAY_FEE_KICK_OFF_1 + MIN_RELAY_FEE_START_TIME + DUST_AMOUNT * 2,
    );
    let kick_off_1_funding_utxo_address = config.connector_6.generate_taproot_address();
    funding_inputs.push((&kick_off_1_funding_utxo_address, kick_off_1_input_amount));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &config.client_0,
        &config.operator_context,
        &kick_off_1_funding_utxo_address,
        &config.connector_1,
        &config.connector_2,
        &config.connector_6,
        kick_off_1_input_amount,
        &config.commitment_secrets,
    )
    .await;

    // start time
    let vout = 2;
    let start_time_input_0 = Input {
        outpoint: OutPoint {
            // connector 2
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };
    let mut start_time = StartTimeTransaction::new(
        &config.operator_context,
        &config.connector_2,
        start_time_input_0,
    );

    start_time.sign(
        &config.operator_context,
        &config.connector_2,
        get_start_time_block_number(config.network),
        &config.commitment_secrets[&CommitmentMessageId::StartTime],
    );

    let start_time_tx = start_time.finalize();
    // start time output should only have dust left
    check_tx_output_sum(DUST_AMOUNT, &start_time_tx);
    // mine start time timeout
    wait_timelock_expiry(config.network, Some("kick off 1 connector 1")).await;
    let start_time_result = config.client_0.esplora.broadcast(&start_time_tx).await;
    println!("Start time tx result: {:?}\n", start_time_result);
    assert!(start_time_result.is_ok());
}
