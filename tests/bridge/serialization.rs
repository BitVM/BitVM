use bitcoin::Amount;

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graph::ONE_HUNDRED,
    transactions::{
        assert::AssertTransaction,
        bridge::{deserialize, serialize, BridgeTransaction, Input},
    },
};

use super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_txn_serialization() {
    let (client, context, _, connector_b, _, _, _, _) = setup_test();

    let input_value = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_outpoint = generate_stub_outpoint(
        &client,
        &connector_b.generate_taproot_address(),
        input_value,
    )
    .await;

    let mut assert_tx = AssertTransaction::new(
        &context,
        Input {
            outpoint: funding_outpoint,
            amount: input_value,
        },
    );

    assert_tx.pre_sign(&context);

    let json = serialize(&assert_tx);
    assert!(json.len() > 0);
    let deserialized_assert_tx = deserialize::<AssertTransaction>(&json);
    assert!(assert_tx == deserialized_assert_tx);
}
