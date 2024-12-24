use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_PEG_IN_DEPOSIT},
        peg_in_deposit::PegInDepositTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_relay_fee, generate_stub_outpoint},
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_peg_in_deposit_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount = Amount::from_sat(INITIAL_AMOUNT + MIN_RELAY_FEE_PEG_IN_DEPOSIT);
    let address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    faucet.fund_input(&address, amount).await.wait().await;
    let outpoint = generate_stub_outpoint(&config.client_0, &address, amount).await;

    let mut peg_in_deposit_tx = PegInDepositTransaction::new(
        &config.depositor_context,
        &config.connector_z,
        Input { outpoint, amount },
    );

    println!(
        "Depositor public key: {:?}\n",
        &config.depositor_context.depositor_public_key
    );

    let tx = peg_in_deposit_tx.finalize();
    check_relay_fee(INITIAL_AMOUNT, &tx);
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Peg in deposit tx result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
