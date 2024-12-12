use std::time::Duration;
use tokio::time::sleep;

use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        disprove_chain::DisproveChainTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::verify_funding_inputs,
    integration::peg_out::utils::create_and_mine_kick_off_2_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_disprove_chain_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_2_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_2_funding_utxo_address = config.connector_1.generate_taproot_address();
    funding_inputs.push((&kick_off_2_funding_utxo_address, kick_off_2_input_amount));

    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;
    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    // kick-off 2
    let (kick_off_2_tx, kick_off_2_txid) = create_and_mine_kick_off_2_tx(
        &config.client_0,
        &config.operator_context,
        &config.connector_1,
        &kick_off_2_funding_utxo_address,
        kick_off_2_input_amount,
        &config.commitment_secrets,
    )
    .await;

    // disprove chain
    let vout = 1; // connector B
    let disprove_chain_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };

    let mut disprove_chain = DisproveChainTransaction::new(
        &config.operator_context,
        &config.connector_b,
        disprove_chain_input_0,
    );

    let secret_nonces_0 = disprove_chain.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_chain.push_nonces(&config.verifier_1_context);

    disprove_chain.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    disprove_chain.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    disprove_chain.add_output(reward_address.script_pubkey());

    let disprove_chain_tx = disprove_chain.finalize();
    let disprove_chain_txid = disprove_chain_tx.compute_txid();

    // mine disprove chain
    let disprove_chain_wait_timeout = Duration::from_secs(20);
    println!(
        "Waiting \x1b[37;41m{:?}\x1b[0m before broadcasting disprove chain tx...",
        disprove_chain_wait_timeout
    );
    sleep(disprove_chain_wait_timeout).await;
    let disprove_chain_result = config.client_0.esplora.broadcast(&disprove_chain_tx).await;
    println!("disprove chain result: {:?}", disprove_chain_result);
    assert!(disprove_chain_result.is_ok());

    // reward balance
    let reward_utxos = config
        .client_0
        .esplora
        .get_address_utxo(reward_address)
        .await
        .unwrap();
    let reward_utxo = reward_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == disprove_chain_txid);

    // assert
    assert!(reward_utxo.is_some());
    assert_eq!(
        reward_utxo.unwrap().value,
        disprove_chain_tx.output[1].value
    );
}
