use bitcoin::{consensus::encode::serialize_hex, Address, Amount};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::DUST_AMOUNT,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_START_TIME_TIMEOUT},
        pre_signed_musig2::PreSignedMusig2Transaction,
        start_time_timeout::StartTimeTimeoutTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_relay_fee, generate_stub_outpoint, get_reward_amount, verify_funding_inputs},
    setup::{setup_test, ONE_HUNDRED},
};

#[tokio::test]
async fn test_start_time_timeout_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let reward_amount = get_reward_amount(ONE_HUNDRED);
    let input_value0 = Amount::from_sat(reward_amount + MIN_RELAY_FEE_START_TIME_TIMEOUT);
    let funding_utxo_address0 = config.connector_2.generate_taproot_address();
    funding_inputs.push((&funding_utxo_address0, input_value0));

    let input_value1 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address1 = config.connector_1.generate_taproot_address();
    funding_inputs.push((&funding_utxo_address1, input_value1));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    let funding_outpoint0 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address0, input_value0).await;
    let funding_outpoint1 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address1, input_value1).await;

    let mut start_time_timeout_tx = StartTimeTimeoutTransaction::new(
        &config.operator_context,
        &config.connector_1,
        &config.connector_2,
        Input {
            outpoint: funding_outpoint0,
            amount: input_value0,
        },
        Input {
            outpoint: funding_outpoint1,
            amount: input_value1,
        },
    );

    let secret_nonces_0 = start_time_timeout_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = start_time_timeout_tx.push_nonces(&config.verifier_1_context);

    start_time_timeout_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_1,
        &config.connector_2,
        &secret_nonces_0,
    );
    start_time_timeout_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_1,
        &config.connector_2,
        &secret_nonces_1,
    );

    let tx = start_time_timeout_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    check_relay_fee(reward_amount + DUST_AMOUNT, &tx);
    println!(
        ">>>>>> MINE START TIME TIMEOUT TX input 0 amount: {:?}, virtual size: {:?}, outputs: {:?}",
        input_value0,
        tx.vsize(),
        tx.output
            .iter()
            .map(|o| o.value.to_sat())
            .collect::<Vec<u64>>(),
    );
    println!(
        ">>>>>> START TIME TIMEOUT TX OUTPUTS SIZE: {:?}",
        tx.output.iter().map(|o| o.size()).collect::<Vec<usize>>()
    );
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Start time timeout tx result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
