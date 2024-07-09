use bitcoin::Amount;

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::ONE_HUNDRED,
    transactions::{
        assert::AssertTransaction,
        base::{deserialize, serialize, Input},
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_assert_tx_serialization() {
    let (client, _, operator_context, verifier_context, _, _, connector_b, _, _, _, _, _, _, _) =
        setup_test();

    let input_value = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_outpoint = generate_stub_outpoint(
        &client,
        &connector_b.generate_taproot_address(),
        input_value,
    )
    .await;

    let mut assert_tx = AssertTransaction::new(
        &operator_context,
        Input {
            outpoint: funding_outpoint,
            amount: input_value,
        },
    );

    assert_tx.pre_sign(&verifier_context);

    let json = serialize(&assert_tx);
    assert!(json.len() > 0);
    let deserialized_assert_tx = deserialize::<AssertTransaction>(&json);
    assert!(assert_tx == deserialized_assert_tx);
}
