use std::time::Duration;
use tokio::time::sleep;

use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::{
        base::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT, MESSAGE_COMMITMENT_FEE_AMOUNT},
        peg_out::CommitmentMessageId,
    },
    superblock::get_start_time_block_number,
    transactions::{
        base::{BaseTransaction, Input},
        start_time::StartTimeTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::verify_funding_inputs,
    integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_start_time_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_1_input_amount = Amount::from_sat(
        INITIAL_AMOUNT + 2 * DUST_AMOUNT + 2 * MESSAGE_COMMITMENT_FEE_AMOUNT + FEE_AMOUNT,
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
        get_start_time_block_number(),
        &config.commitment_secrets[&CommitmentMessageId::StartTime],
    );

    let start_time_tx = start_time.finalize();

    // mine start time
    let start_time_wait_timeout = Duration::from_secs(20);
    println!(
        "Waiting \x1b[37;41m{:?}\x1b[0m before broadcasting start time tx...",
        start_time_wait_timeout
    );
    sleep(start_time_wait_timeout).await;
    let start_time_result = config.client_0.esplora.broadcast(&start_time_tx).await;
    println!("Broadcast result: {:?}\n", start_time_result);
    assert!(start_time_result.is_ok());
}
