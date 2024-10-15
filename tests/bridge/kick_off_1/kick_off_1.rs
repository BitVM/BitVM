use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT, MESSAGE_COMMITMENT_FEE_AMOUNT},
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_1::KickOff1Transaction,
    },
};

use crate::bridge::helper::generate_stub_outpoint;

use super::super::setup::setup_test;

#[tokio::test]
async fn test_kick_off_1_tx() {
    let config = setup_test().await;

    let input_amount =
        Amount::from_sat(INITIAL_AMOUNT + MESSAGE_COMMITMENT_FEE_AMOUNT * 2 + FEE_AMOUNT);
    let funding_address = config.connector_6.generate_taproot_address();
    let funding_outpoint_0 =
        generate_stub_outpoint(&config.client_0, &funding_address, input_amount).await;

    let input = Input {
        outpoint: funding_outpoint_0,
        amount: input_amount,
    };

    let mut kick_off_1_tx = KickOff1Transaction::new(
        &config.operator_context,
        &config.connector_1,
        &config.connector_2,
        &config.connector_6,
        input,
    );
    let ethereum_txid = "8b274fbb76c72f66c467c976c61d5ac212620e036818b5986a33f7b557cb2de8";
    let bitcoin_txid = "8b4cce4a1a9522392c095df6416533d89e1e6ac7bdf8ab3c1685426b321ed182";
    kick_off_1_tx.sign(
        &config.operator_context,
        &config.connector_6,
        bitcoin_txid.as_bytes(),
        ethereum_txid.as_bytes(),
        &config.connector_6_winternitz_secrets[&0],
    );

    let tx = kick_off_1_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    assert!(result.is_ok());
}
