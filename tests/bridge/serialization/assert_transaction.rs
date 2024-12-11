use bitcoin::Amount;

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::ONE_HUNDRED,
    serialization::{deserialize, serialize},
    transactions::{
        assert::AssertTransaction, base::Input, pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_assert_tx_serialization() {
    let config = setup_test().await;

    let amount = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &config.connector_b.generate_taproot_address(),
        amount,
    )
    .await;

    let mut assert_tx = AssertTransaction::new(
        &config.connector_4,
        &config.connector_5,
        &config.connector_b,
        &config.connector_c,
        Input { outpoint, amount },
    );

    let secret_nonces_0 = assert_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_tx.push_nonces(&config.verifier_1_context);

    assert_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    assert_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let json = serialize(&assert_tx);
    assert!(json.len() > 0);
    let deserialized_assert_tx = deserialize::<AssertTransaction>(&json);
    assert!(assert_tx == deserialized_assert_tx);
}
