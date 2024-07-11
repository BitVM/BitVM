use bitcoin::{Amount, OutPoint};

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, InputWithScript},
        challenge::ChallengeTransaction,
    },
};

use crate::bridge::{
    helper::generate_stub_outpoint, integration::peg_out::utils::create_and_mine_kick_off_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_challenge_success() {
    let (client, depositor_context, operator_context, _, _, _, _, _, _, _, _, _, _, _) =
        setup_test().await;

    // kick-off
    let (kick_off_tx, kick_off_tx_id) =
        create_and_mine_kick_off_tx(&client, &operator_context).await;

    // challenge
    let challenge_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let challenge_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    let challenge_funding_outpoint = generate_stub_outpoint(
        &client,
        &challenge_funding_utxo_address,
        challenge_input_amount,
    )
    .await;
    let challenge_crowdfunding_input = InputWithScript {
        outpoint: challenge_funding_outpoint,
        amount: challenge_input_amount,
        script: &generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
    };

    let kick_off_output_index = 1; // connectorA
    let challenge_kick_off_outpoint = OutPoint {
        txid: kick_off_tx_id,
        vout: kick_off_output_index,
    };
    let challenge_kick_off_input = Input {
        outpoint: challenge_kick_off_outpoint,
        amount: kick_off_tx.output[kick_off_output_index as usize].value,
    };

    let mut challenge = ChallengeTransaction::new(
        &operator_context,
        challenge_kick_off_input,
        challenge_input_amount,
    );
    challenge.add_inputs_and_output(
        &depositor_context,
        &vec![challenge_crowdfunding_input],
        &depositor_context.depositor_keypair,
        generate_pay_to_pubkey_script(&depositor_context.depositor_public_key),
    ); // add crowdfunding input
    let challenge_tx = challenge.finalize();
    let challenge_tx_id = challenge_tx.compute_txid();

    // mine challenge tx
    let challenge_result = client.esplora.broadcast(&challenge_tx).await;
    assert!(challenge_result.is_ok());

    // operator balance
    let operator_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    let operator_utxos = client
        .esplora
        .get_address_utxo(operator_address)
        .await
        .unwrap();
    let operator_utxo = operator_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == challenge_tx_id);

    // assert
    assert!(operator_utxo.is_some());
    assert_eq!(operator_utxo.unwrap().value, challenge_tx.output[0].value);
}
