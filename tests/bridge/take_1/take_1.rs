use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::connector::{P2wshConnector, TaprootConnector},
    graphs::base::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT, ONE_HUNDRED},
    transactions::{
        base::{BaseTransaction, Input},
        take_1::Take1Transaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_take_1_tx() {
    let (
        client,
        _,
        _,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        _,
        connector_a,
        connector_b,
        _,
        _,
        connector_0,
        _,
        _,
        connector_3,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test().await;

    let input_value0 = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let funding_utxo_address0 = connector_0.generate_taproot_address();
    let funding_outpoint0 =
        generate_stub_outpoint(&client, &funding_utxo_address0, input_value0).await;

    let input_value1 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address1 = connector_a.generate_taproot_address();
    let funding_outpoint1 =
        generate_stub_outpoint(&client, &funding_utxo_address1, input_value1).await;

    let input_value2 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address2 = connector_3.generate_address();
    let funding_outpoint2 =
        generate_stub_outpoint(&client, &funding_utxo_address2, input_value2).await;

    let input_value3 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo_address3 = connector_b.generate_taproot_address();
    let funding_outpoint3 =
        generate_stub_outpoint(&client, &funding_utxo_address3, input_value3).await;

    let mut take_1_tx = Take1Transaction::new(
        &operator_context,
        Input {
            outpoint: funding_outpoint0,
            amount: input_value0,
        },
        Input {
            outpoint: funding_outpoint1,
            amount: input_value1,
        },
        Input {
            outpoint: funding_outpoint2,
            amount: input_value2,
        },
        Input {
            outpoint: funding_outpoint3,
            amount: input_value3,
        },
    );

    let secret_nonces_0 = take_1_tx.push_nonces(&verifier_0_context);
    let secret_nonces_1 = take_1_tx.push_nonces(&verifier_1_context);

    take_1_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
    take_1_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

    let tx = take_1_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
