use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint};

use bitvm::bridge::{
    components::{
        bridge::BridgeTransaction, connector_z::generate_taproot_address, helper::*,
        peg_in_confirm::PegInConfirmTransaction,
    },
    graph::{FEE_AMOUNT, INITIAL_AMOUNT},
};

use super::super::setup::setup_test;

#[tokio::test]
async fn test_peg_in_confirm_tx() {
    let (client, context) = setup_test();

    let evm_address = String::from("evm address");

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT;
    let input_amount = Amount::from_sat(input_amount_raw);
    let funding_address = generate_taproot_address(
        &evm_address,
        &context.n_of_n_taproot_public_key.unwrap(),
        &context.depositor_taproot_public_key.unwrap(),
    );

    let funding_utxo_0 = client
        .get_initial_utxo(funding_address.clone(), input_amount)
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                funding_address.clone(),
                input_amount_raw
            );
        });

    let funding_outpoint_0 = OutPoint {
        txid: funding_utxo_0.txid,
        vout: funding_utxo_0.vout,
    };

    let input = Input {
        outpoint: funding_outpoint_0,
        amount: input_amount,
    };

    let mut peg_in_confirm_tx = PegInConfirmTransaction::new(&context, input, evm_address);

    peg_in_confirm_tx.pre_sign(&context);
    let tx = peg_in_confirm_tx.finalize(&context);
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
