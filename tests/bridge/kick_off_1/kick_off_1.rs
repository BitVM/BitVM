use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_1::KickOff1Transaction,
    },
};

use crate::bridge::helper::generate_stub_outpoint;

use super::super::setup::setup_test;

#[tokio::test]
async fn test_kick_off_1_tx() {
    let (client, _, _, operator_context, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) =
        setup_test().await;

    let input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let funding_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    let funding_outpoint_0 = generate_stub_outpoint(&client, &funding_address, input_amount).await;

    let input = Input {
        outpoint: funding_outpoint_0,
        amount: input_amount,
    };

    let kick_off_1_tx = KickOff1Transaction::new(&operator_context, input);

    let tx = kick_off_1_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
