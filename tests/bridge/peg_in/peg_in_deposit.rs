use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint};

use bitvm::bridge::{
    graph::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_deposit::PegInDepositTransaction,
    },
};

use super::super::setup::setup_test;

#[tokio::test]
async fn test_peg_in_deposit_tx() {
    let (client, depositor_context, _, _, _, _, _, _, _, _, _, _, _) = setup_test();

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT;
    let input_amount = Amount::from_sat(input_amount_raw);
    let funding_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
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

    let peg_in_deposit_tx = PegInDepositTransaction::new(
        &depositor_context,
        input,
        depositor_context.evm_address.clone(),
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
