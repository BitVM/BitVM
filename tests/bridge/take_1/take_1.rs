use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::base::{P2wshConnector, TaprootConnector},
    graphs::base::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT, ONE_HUNDRED},
    transactions::{
        base::{BaseTransaction, Input},
        take_1::Take1Transaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_take_1_tx() {
    let config = setup_test().await;

    let input_value0 = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let funding_utxo_address0 = config.connector_0.generate_taproot_address();
    let funding_outpoint0 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address0, input_value0).await;

    let input_value1 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address1 = config.connector_a.generate_taproot_address();
    let funding_outpoint1 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address1, input_value1).await;

    let input_value2 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address2 = config.connector_3.generate_address();
    let funding_outpoint2 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address2, input_value2).await;

    let input_value3 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo_address3 = config.connector_b.generate_taproot_address();
    let funding_outpoint3 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address3, input_value3).await;

    let mut take_1_tx = Take1Transaction::new(
        &config.operator_context,
        &config.connector_0,
        &config.connector_3,
        &config.connector_a,
        &config.connector_b,
        Input {
            outpoint: funding_outpoint0,
            amount: input_value0,
        },
        Input {
            outpoint: funding_outpoint1,
            amount: input_value1,
        },
        Input {
            outpoint: funding_outpoint2,
            amount: input_value2,
        },
        Input {
            outpoint: funding_outpoint3,
            amount: input_value3,
        },
    );

    let secret_nonces_0 = take_1_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = take_1_tx.push_nonces(&config.verifier_1_context);

    take_1_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_0,
        &config.connector_b,
        &secret_nonces_0,
    );
    take_1_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_0,
        &config.connector_b,
        &secret_nonces_1,
    );

    let tx = take_1_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
