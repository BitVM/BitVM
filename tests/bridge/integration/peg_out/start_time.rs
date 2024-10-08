use std::time::Duration;
use tokio::time::sleep;

use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        start_time::StartTimeTransaction,
    },
};

use crate::bridge::{
    helper::verify_funding_inputs, integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_start_time_success() {
    let (client, _, _, operator_context, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) =
        setup_test().await;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_1_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_1_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    funding_inputs.push((&kick_off_1_funding_utxo_address, kick_off_1_input_amount));

    verify_funding_inputs(&client, &funding_inputs).await;

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &client,
        &operator_context,
        &kick_off_1_funding_utxo_address,
        kick_off_1_input_amount,
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
    let start_time = StartTimeTransaction::new(&operator_context, start_time_input_0);

    let start_time_tx = start_time.finalize();

    // mine start time
    sleep(Duration::from_secs(60)).await;
    let start_time_result = client.esplora.broadcast(&start_time_tx).await;
    assert!(start_time_result.is_ok());
}
