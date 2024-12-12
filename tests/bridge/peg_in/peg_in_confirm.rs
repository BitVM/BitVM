use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_confirm::PegInConfirmTransaction,
    },
};

use crate::bridge::faucet::{Faucet, FaucetType};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_in_confirm_tx() {
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

    let mut peg_in_confirm_tx = PegInConfirmTransaction::new(
        &config.depositor_context,
        &config.connector_0,
        &config.connector_z,
        Input { outpoint, amount },
    );

    let secret_nonces_0 = peg_in_confirm_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = peg_in_confirm_tx.push_nonces(&config.verifier_1_context);

    peg_in_confirm_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_z,
        &secret_nonces_0,
    );
    peg_in_confirm_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_z,
        &secret_nonces_1,
    );

    let tx = peg_in_confirm_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
