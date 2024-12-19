use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input, MIN_RELAY_FEE_ASSERT},
        pre_signed::PreSignedTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_relay_fee, generate_stub_outpoint},
    setup::{setup_test, ONE_HUNDRED},
};

#[tokio::test]
async fn test_assert_tx_success() {
    let config = setup_test().await;

    let amount = Amount::from_sat(ONE_HUNDRED + MIN_RELAY_FEE_ASSERT);
    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    faucet
        .fund_input(&config.connector_b.generate_taproot_address(), amount)
        .await
        .wait()
        .await;

    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &config.connector_b.generate_taproot_address(),
        amount,
    )
    .await;

    let mut assert_tx = AssertTransaction::new(
        &config.connector_4,
        &config.connector_5,
        &config.connector_b,
        &config.connector_c,
        Input { outpoint, amount },
    );

    let secret_nonces_0 = assert_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_tx.push_nonces(&config.verifier_1_context);

    assert_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    assert_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    println!(
        "tx output before finalize: {:?}",
        assert_tx
            .tx()
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .collect::<Vec<u64>>()
    );
    let tx = assert_tx.finalize();
    println!(
        "tx output after finalize: {:?}",
        assert_tx
            .tx()
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .collect::<Vec<u64>>()
    );
    check_relay_fee(ONE_HUNDRED, &tx);
    println!("Script Path Spend Transaction: {:?}\n", tx);
    println!(
        ">>>>>> MINE ASSERT input amount: {:?}, virtual size: {:?}, output 1: {:?}",
        amount,
        tx.vsize(),
        tx.output[1].value.to_sat()
    );
    println!(
        ">>>>>> ASSERT TX OUTPUTS SIZE: {:?}",
        tx.output.iter().map(|o| o.size()).collect::<Vec<usize>>()
    );
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Assert tx result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
