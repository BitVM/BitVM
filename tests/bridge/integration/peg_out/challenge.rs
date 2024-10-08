use bitcoin::{Address, Amount, OutPoint};

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, InputWithScript},
        challenge::ChallengeTransaction,
    },
};

use crate::bridge::{
    helper::{generate_stub_outpoint, verify_funding_inputs},
    integration::peg_out::utils::create_and_mine_kick_off_1_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_challenge_success() {
    let (
        client,
        _,
        depositor_context,
        operator_context,
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

    let challenge_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let challenge_funding_utxo_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );
    funding_inputs.push((&challenge_funding_utxo_address, challenge_input_amount));

    verify_funding_inputs(&client, &funding_inputs).await;

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &client,
        &operator_context,
        &kick_off_1_funding_utxo_address,
        kick_off_1_input_amount,
    )
    .await;

    // challenge
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

    let vout = 0; // connector A
    let challenge_kick_off_input = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
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
    let challenge_txid = challenge_tx.compute_txid();

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
        .find(|x| x.txid == challenge_txid);

    // assert
    assert!(operator_utxo.is_some());
    assert_eq!(operator_utxo.unwrap().value, challenge_tx.output[0].value);
}
