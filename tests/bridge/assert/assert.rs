use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::ONE_HUNDRED,
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_assert_tx() {
    let (
        client,
        _,
        _,
        operator_context,
        verifier0_context,
        verifier1_context,
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
    ) = setup_test().await;

    let amount = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint =
        generate_stub_outpoint(&client, &connector_b.generate_taproot_address(), amount).await;

    let mut assert_tx = AssertTransaction::new(&operator_context, Input { outpoint, amount });

    let secret_nonces0 = assert_tx.push_nonces(&verifier0_context);
    let secret_nonces1 = assert_tx.push_nonces(&verifier1_context);

    assert_tx.pre_sign(&verifier0_context, &secret_nonces0);
    assert_tx.pre_sign(&verifier1_context, &secret_nonces1);

    let tx = assert_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
