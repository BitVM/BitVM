use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::ONE_HUNDRED,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_timeout::KickOffTimeoutTransaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_kick_off_timeout_tx() {
    let (
        client,
        _,
        _,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        _,
        _,
        _,
        _,
        connector_1,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test().await;

    let input_value0 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint_0 = generate_stub_outpoint(
        &client,
        &connector_1.generate_taproot_address(),
        input_value0,
    )
    .await;

    let mut kick_off_timeout_tx = KickOffTimeoutTransaction::new(
        &operator_context,
        Input {
            outpoint: outpoint_0,
            amount: input_value0,
        },
    );

    let secret_nonces_0 = kick_off_timeout_tx.push_nonces(&verifier_0_context);
    let secret_nonces_1 = kick_off_timeout_tx.push_nonces(&verifier_1_context);

    kick_off_timeout_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
    kick_off_timeout_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

    let tx = kick_off_timeout_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
