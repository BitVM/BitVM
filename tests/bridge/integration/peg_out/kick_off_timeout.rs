use std::time::Duration;
use tokio::time::sleep;

use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_timeout::KickOffTimeoutTransaction,
    },
};

use crate::bridge::{
    helper::verify_funding_inputs, integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_kick_off_timeout_success() {
    let (
        client,
        _,
        _,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        withdrawer_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test().await;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_1_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_1_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    funding_inputs.push((&kick_off_1_funding_utxo_address, kick_off_1_input_amount));

    verify_funding_inputs(&client, &funding_inputs).await;

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &client,
        &operator_context,
        &kick_off_1_funding_utxo_address,
        kick_off_1_input_amount,
    )
    .await;

    // kick-off timeout
    let vout = 1; // connector 1
    let kick_off_timeout_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout: vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };

    let mut kick_off_timeout =
        KickOffTimeoutTransaction::new(&operator_context, kick_off_timeout_input_0);

    let secret_nonces_0 = kick_off_timeout.push_nonces(&verifier_0_context);
    let secret_nonces_1 = kick_off_timeout.push_nonces(&verifier_1_context);

    kick_off_timeout.pre_sign(&verifier_0_context, &secret_nonces_0);
    kick_off_timeout.pre_sign(&verifier_1_context, &secret_nonces_1);

    let reward_address = generate_pay_to_pubkey_script_address(
        withdrawer_context.network,
        &withdrawer_context.withdrawer_public_key,
    );
    kick_off_timeout.add_output(reward_address.script_pubkey());

    let kick_off_timeout_tx = kick_off_timeout.finalize();
    let kick_off_timeout_txid = kick_off_timeout_tx.compute_txid();

    // mine kick-off timeout
    sleep(Duration::from_secs(60)).await;
    let kick_off_timeout_result = client.esplora.broadcast(&kick_off_timeout_tx).await;
    assert!(kick_off_timeout_result.is_ok());

    // reward balance
    let reward_utxos = client
        .esplora
        .get_address_utxo(reward_address)
        .await
        .unwrap();
    let reward_utxo = reward_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == kick_off_timeout_txid);

    // assert
    assert!(reward_utxo.is_some());
    assert_eq!(
        reward_utxo.unwrap().value,
        kick_off_timeout_tx.output[1].value
    );
}
