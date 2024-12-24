use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::DUST_AMOUNT,
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        assert::AssertTransaction,
        base::{
            BaseTransaction, Input, MIN_RELAY_FEE_ASSERT, MIN_RELAY_FEE_DISPROVE,
            MIN_RELAY_FEE_KICK_OFF_2,
        },
        disprove::DisproveTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_relay_fee, verify_funding_inputs, wait_for_timelock_to_timeout},
    integration::peg_out::utils::create_and_mine_kick_off_2_tx,
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_disprove_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_2_input_amount = Amount::from_sat(
        INITIAL_AMOUNT
            + MIN_RELAY_FEE_KICK_OFF_2
            + DUST_AMOUNT
            + MIN_RELAY_FEE_ASSERT
            + DUST_AMOUNT // assert has one more dust output
            + MIN_RELAY_FEE_DISPROVE,
    );
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

    // assert
    let vout = 1; // connector B
    let assert_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };
    let mut assert = AssertTransaction::new(
        &config.connector_4,
        &config.connector_5,
        &config.connector_b,
        &config.connector_c,
        assert_input_0,
    );

    let secret_nonces_0 = assert.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert.push_nonces(&config.verifier_1_context);

    assert.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    assert.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let assert_tx = assert.finalize();
    let assert_txid = assert_tx.compute_txid();
    wait_for_timelock_to_timeout(
        config.operator_context.network,
        Some("kick off 2 connector 3"),
    )
    .await;
    let assert_result = config.client_0.esplora.broadcast(&assert_tx).await;
    println!("Assert tx result: {assert_result:?}");
    assert!(assert_result.is_ok());

    // disprove
    let vout = 1;
    let script_index = 1;
    let disprove_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };

    let vout = 2;
    let disprove_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };

    let mut disprove = DisproveTransaction::new(
        &config.operator_context,
        &config.connector_5,
        &config.connector_c,
        disprove_input_0,
        disprove_input_1,
        script_index,
    );

    let secret_nonces_0 = disprove.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove.push_nonces(&config.verifier_1_context);

    disprove.pre_sign(
        &config.verifier_0_context,
        &config.connector_5,
        &secret_nonces_0,
    );
    disprove.pre_sign(
        &config.verifier_1_context,
        &config.connector_5,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove.add_input_output(&config.connector_c, script_index, verifier_reward_script);

    let disprove_tx = disprove.finalize();
    let disprove_txid = disprove_tx.compute_txid();

    // mine disprove
    check_relay_fee(INITIAL_AMOUNT, &disprove_tx);
    wait_for_timelock_to_timeout(config.operator_context.network, Some("Assert connector 4")).await;
    let disprove_result = config.client_0.esplora.broadcast(&disprove_tx).await;
    println!("Disprove tx result: {disprove_result:?}");
    assert!(disprove_result.is_ok());

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
        .find(|x| x.txid == disprove_txid);

    // assert
    assert!(reward_utxo.is_some());
    assert_eq!(reward_utxo.unwrap().value, disprove_tx.output[1].value);
}
