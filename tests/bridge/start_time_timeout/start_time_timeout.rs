use bitcoin::{consensus::encode::serialize_hex, Address, Amount};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{DUST_AMOUNT, ONE_HUNDRED},
    transactions::{
        base::{BaseTransaction, Input},
        start_time_timeout::StartTimeTimeoutTransaction,
    },
};

use crate::bridge::helper::verify_funding_inputs;

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_start_time_timeout_tx() {
    let config = setup_test().await;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let input_value0 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo_address0 = config.connector_2.generate_taproot_address();
    funding_inputs.push((&funding_utxo_address0, input_value0));

    let input_value1 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address1 = config.connector_1.generate_taproot_address();
    funding_inputs.push((&funding_utxo_address1, input_value1));

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
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
