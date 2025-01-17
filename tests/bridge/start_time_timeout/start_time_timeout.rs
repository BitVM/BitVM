use bitcoin::{Address, Amount};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::DUST_AMOUNT,
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_START_TIME_TIMEOUT},
        pre_signed_musig2::PreSignedMusig2Transaction,
        start_time_timeout::StartTimeTimeoutTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{
        check_tx_output_sum, generate_stub_outpoint, get_reward_amount, verify_funding_inputs,
        wait_timelock_expiry,
    },
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
    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    start_time_timeout_tx.add_output(reward_address.script_pubkey());

    let tx = start_time_timeout_tx.finalize();
    check_tx_output_sum(reward_amount + DUST_AMOUNT, &tx);
    wait_timelock_expiry(config.network, Some("kick off 1 connector 1")).await;
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Start time timeout tx result: {:?}\n", result);
    assert!(result.is_ok());
}
