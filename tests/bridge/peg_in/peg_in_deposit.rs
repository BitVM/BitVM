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
    let (
        client,
        _,
        depositor_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test().await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let outpoint = generate_stub_outpoint(
        &client,
        &generate_pay_to_pubkey_script_address(
            depositor_context.network,
            &depositor_context.depositor_public_key,
        ),
        amount,
    )
    .await;

    let peg_in_deposit_tx = PegInDepositTransaction::new(
        &depositor_context,
        &depositor_evm_address,
        Input { outpoint, amount },
    );

    println!(
        "Depositor public key: {:?}\n",
        &depositor_context.depositor_public_key
    );

    let tx = peg_in_deposit_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
