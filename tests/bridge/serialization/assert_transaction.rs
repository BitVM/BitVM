use bitcoin::Amount;

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::ONE_HUNDRED,
    serialization::{deserialize, serialize},
    transactions::{assert::AssertTransaction, base::Input},
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_assert_tx_serialization() {
    let (
        client,
        _,
        _,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        connector_b,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test().await;

    let amount = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint =
        generate_stub_outpoint(&client, &connector_b.generate_taproot_address(), amount).await;

    let mut assert_tx = AssertTransaction::new(&operator_context, Input { outpoint, amount });

    let secret_nonces_0 = assert_tx.push_nonces(&verifier_0_context);
    let secret_nonces_1 = assert_tx.push_nonces(&verifier_1_context);

    assert_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
    assert_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

    let json = serialize(&assert_tx);
    assert!(json.len() > 0);
    let deserialized_assert_tx = deserialize::<AssertTransaction>(&json);
    assert!(assert_tx == deserialized_assert_tx);
}
