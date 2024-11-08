use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::ONE_HUNDRED,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_timeout::KickOffTimeoutTransaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_kick_off_timeout_tx() {
    let config = setup_test().await;

    let input_value0 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint_0 = generate_stub_outpoint(
        &config.client_0,
        &config.connector_1.generate_taproot_address(),
        input_value0,
    )
    .await;

    let mut kick_off_timeout_tx = KickOffTimeoutTransaction::new(
        &config.operator_context,
        &config.connector_1,
        Input {
            outpoint: outpoint_0,
            amount: input_value0,
        },
    );

    let secret_nonces_0 = kick_off_timeout_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = kick_off_timeout_tx.push_nonces(&config.verifier_1_context);

    kick_off_timeout_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_1,
        &secret_nonces_0,
    );
    kick_off_timeout_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_1,
        &secret_nonces_1,
    );

    let tx = kick_off_timeout_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
