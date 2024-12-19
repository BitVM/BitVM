use bitcoin::{consensus::encode::serialize_hex, Amount};

use bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_refund::PegInRefundTransaction,
    },
};

use crate::bridge::faucet::{Faucet, FaucetType};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_in_refund_tx() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
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
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
