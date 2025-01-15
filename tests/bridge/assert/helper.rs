use bitcoin::{Amount, Transaction};
use bitvm::bridge::{
    connectors::base::TaprootConnector,
    transactions::{
        assert_transactions::assert_initial::AssertInitialTransaction,
        base::{BaseTransaction, Input},
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use crate::bridge::{
    faucet::Faucet,
    helper::{generate_stub_outpoint, wait_timelock_expiry},
    setup::SetupConfig,
};

pub async fn create_and_mine_assert_initial_tx(
    config: &SetupConfig,
    faucet: &Faucet,
    input_amount: Amount,
) -> Transaction {
    faucet
        .fund_input(&config.connector_b.generate_taproot_address(), input_amount)
        .await
        .wait()
        .await;

    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &config.connector_b.generate_taproot_address(),
        input_amount,
    )
    .await;

    let mut assert_initial_tx = AssertInitialTransaction::new(
        &config.connector_b,
        &config.connector_d,
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_e_2,
        Input {
            outpoint,
            amount: input_amount,
        },
    );

    let secret_nonces_0 = assert_initial_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_initial_tx.push_nonces(&config.verifier_1_context);

    assert_initial_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    assert_initial_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let tx = assert_initial_tx.finalize();
    wait_timelock_expiry(config.network, Some("kick off 2 connector b")).await;
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Assert initial tx result: {:?}\n", result);
    assert!(result.is_ok());

    tx
}
