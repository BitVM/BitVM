use super::setup::setup_test;
use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint, Network};
use bitvm::bridge::{
    components::{
        assert::AssertTransaction, bridge::BridgeTransaction, connector_b::ConnectorB, helper::Input,
    },
    graph::ONE_HUNDRED,
};

#[tokio::test]
async fn test_assert_tx() {
    let (client, context) = setup_test();

    let connector_b = ConnectorB::new(Network::Testnet, &context.n_of_n_taproot_public_key.unwrap());

    let input_value = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo = client
        .get_initial_utxo(
            connector_b.generate_taproot_address(),
            input_value,
        )
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
        &context,
        Input {
            outpoint: funding_outpoint,
            amount: input_value,
        },
    );

    assert_tx.pre_sign(&context);
    let tx = assert_tx.finalize(&context);
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
