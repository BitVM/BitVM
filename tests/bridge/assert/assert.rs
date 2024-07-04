use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint};

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::ONE_HUNDRED,
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
    },
};

use super::super::setup::setup_test;

#[tokio::test]
async fn test_assert_tx() {
    let (client, _, operator_context, verifier_context, _, _, connector_b, _, _, _, _, _, _, _) =
        setup_test();

    let input_value = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo = client
        .get_initial_utxo(connector_b.generate_taproot_address(), input_value)
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                connector_b.generate_taproot_address(),
                input_value.to_sat()
            );
        });
    let funding_outpoint = OutPoint {
        txid: funding_utxo.txid,
        vout: funding_utxo.vout,
    };

    let mut assert_tx = AssertTransaction::new(
        &operator_context,
        Input {
            outpoint: funding_outpoint,
            amount: input_value,
        },
    );

    assert_tx.pre_sign(&verifier_context);
    let tx = assert_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
