use bitcoin::{Amount, Network, Transaction, Txid};
use bridge::{
    connectors::{base::TaprootConnector, connector_b::ConnectorB, connector_d::ConnectorD},
    contexts::verifier::VerifierContext,
    transactions::{
        assert_transactions::{
            assert_initial::AssertInitialTransaction,
            utils::{AssertCommit1ConnectorsE, AssertCommit2ConnectorsE},
        },
        base::{BaseTransaction, Input},
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};
use esplora_client::AsyncClient;

use crate::bridge::{
    faucet::Faucet,
    helper::{generate_stub_outpoint, wait_for_timelock_expiry},
    setup::SetupConfigFull,
};

pub async fn fund_create_and_mine_assert_initial_tx(
    config: &SetupConfigFull,
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

    let (tx, _) = create_and_mine_assert_initial_tx(
        &config.client_0.esplora,
        config.network,
        &config.verifier_0_context,
        &config.verifier_1_context,
        &config.connector_b,
        &config.connector_d,
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_e_2,
        Input {
            outpoint,
            amount: input_amount,
        },
    )
    .await;

    tx
}

pub async fn create_and_mine_assert_initial_tx(
    esplora: &AsyncClient,
    network: Network,
    verifier_0_context: &VerifierContext,
    verifier_1_context: &VerifierContext,
    connector_b: &ConnectorB,
    connector_d: &ConnectorD,
    assert_commit_connectors_e_1: &AssertCommit1ConnectorsE,
    assert_commit_connectors_e_2: &AssertCommit2ConnectorsE,
    input: Input,
) -> (Transaction, Txid) {
    let mut assert_initial_tx = AssertInitialTransaction::new(
        connector_b,
        connector_d,
        assert_commit_connectors_e_1,
        assert_commit_connectors_e_2,
        input,
    );

    let secret_nonces_0 = assert_initial_tx.push_nonces(verifier_0_context);
    let secret_nonces_1 = assert_initial_tx.push_nonces(verifier_1_context);

    assert_initial_tx.pre_sign(verifier_0_context, connector_b, &secret_nonces_0);
    assert_initial_tx.pre_sign(verifier_1_context, connector_b, &secret_nonces_1);

    let tx = assert_initial_tx.finalize();
    let tx_id = tx.compute_txid();
    println!("Txid: {:?}", tx_id);
    wait_for_timelock_expiry(network, Some("kick off 2 connector b")).await;
    let result = esplora.broadcast(&tx).await;
    println!("Assert initial tx result: {:?}\n", result);
    assert!(result.is_ok());

    (tx, tx_id)
}
