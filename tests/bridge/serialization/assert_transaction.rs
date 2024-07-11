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
    let (client, _, operator_context, verifier_context, _, _, connector_b, _, _, _, _, _, _, _) =
        setup_test().await;

    let amount = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint =
        generate_stub_outpoint(&client, &connector_b.generate_taproot_address(), amount).await;

    let mut assert_tx = AssertTransaction::new(&operator_context, Input { outpoint, amount });

    assert_tx.pre_sign(&verifier_context);

    let json = serialize(&assert_tx);
    assert!(json.len() > 0);
    let deserialized_assert_tx = deserialize::<AssertTransaction>(&json);
    assert!(assert_tx == deserialized_assert_tx);
}
