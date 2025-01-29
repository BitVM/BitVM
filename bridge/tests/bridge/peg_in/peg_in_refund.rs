use bitcoin::Amount;

use bridge::{
    connectors::base::TaprootConnector,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_PEG_IN_REFUND},
        peg_in_refund::PegInRefundTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, generate_stub_outpoint, wait_timelock_expiry},
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_peg_in_refund_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount = Amount::from_sat(INITIAL_AMOUNT + MIN_RELAY_FEE_PEG_IN_REFUND);
    faucet
        .fund_input(&config.connector_z.generate_taproot_address(), amount)
        .await
        .wait()
        .await;
    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &config.connector_z.generate_taproot_address(),
        amount,
    )
    .await;

    let peg_in_refund_tx = PegInRefundTransaction::new(
        &config.depositor_context,
        &config.connector_z,
        Input { outpoint, amount },
    );

    let tx = peg_in_refund_tx.finalize();
    check_tx_output_sum(INITIAL_AMOUNT, &tx);
    wait_timelock_expiry(config.network, Some("peg in deposit connector z")).await;
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Peg in refund tx result: {:?}\n", result);
    assert!(result.is_ok());
}
