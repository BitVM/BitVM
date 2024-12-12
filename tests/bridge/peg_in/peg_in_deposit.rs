use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_deposit::PegInDepositTransaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_in_deposit_tx() {
    let config = setup_test().await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &generate_pay_to_pubkey_script_address(
            config.depositor_context.network,
            &config.depositor_context.depositor_public_key,
        ),
        amount,
    )
    .await;

    let peg_in_deposit_tx = PegInDepositTransaction::new(
        &config.depositor_context,
        &config.connector_z,
        Input { outpoint, amount },
    );

    println!(
        "Depositor public key: {:?}\n",
        &config.depositor_context.depositor_public_key
    );

    let tx = peg_in_deposit_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
