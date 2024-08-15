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
    let (client, _, operator_context, verifier_context, _, _, connector_b, _, _, _, _, _, _, _, _) =
        setup_test().await;

    let amount = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let outpoint =
        generate_stub_outpoint(&client, &connector_b.generate_taproot_address(), amount).await;

    let mut assert_tx = AssertTransaction::new(&operator_context, Input { outpoint, amount });

    assert_tx.pre_sign(&verifier_context);
    let tx = assert_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
