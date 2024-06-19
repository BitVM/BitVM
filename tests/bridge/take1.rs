use bitcoin::{consensus::encode::serialize_hex, Amount};
use bitvm::bridge::{
    components::{
        bridge::BridgeTransaction,
        connector_a, connector_b,
        helper::{generate_pay_to_pubkey_script_address, generate_timelock_script_address, Input},
        take1::Take1Transaction,
    },
    graph::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT, ONE_HUNDRED},
};

use crate::bridge::helper::generate_stub_outpoint;

use super::setup::setup_test;

#[tokio::test]
async fn test_take1_tx() {
    let (client, context) = setup_test();

    let input_value0 = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let funding_utxo_address0 =
        generate_pay_to_pubkey_script_address(&context.n_of_n_public_key.unwrap());
    let funding_outpoint0 =
        generate_stub_outpoint(&client, &funding_utxo_address0, input_value0).await;

    let input_value1 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address1 =
        generate_timelock_script_address(&context.n_of_n_public_key.unwrap(), 2);
    let funding_outpoint1 =
        generate_stub_outpoint(&client, &funding_utxo_address1, input_value1).await;

    let input_value2 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address2 = connector_a::generate_taproot_address(
        &context.operator_taproot_public_key.unwrap(),
        &context.n_of_n_taproot_public_key.unwrap(),
    );
    let funding_outpoint2 =
        generate_stub_outpoint(&client, &funding_utxo_address2, input_value2).await;

    let input_value3 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo_address3 =
        connector_b::generate_taproot_address(&context.n_of_n_taproot_public_key.unwrap());
    let funding_outpoint3 =
        generate_stub_outpoint(&client, &funding_utxo_address3, input_value3).await;

    let mut take1_tx = Take1Transaction::new(
        &context,
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

    take1_tx.pre_sign(&context);
    let tx = take1_tx.finalize(&context);
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
