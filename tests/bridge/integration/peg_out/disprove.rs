use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
        disprove::DisproveTransaction,
    },
};

use crate::bridge::{
    helper::verify_funding_inputs, integration::peg_out::utils::create_and_mine_kick_off_2_tx,
    setup::setup_test,
};

#[tokio::test]
async fn test_disprove_success() {
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
    ) = setup_test().await;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_2_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_2_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    funding_inputs.push((&kick_off_2_funding_utxo_address, kick_off_2_input_amount));

    verify_funding_inputs(&client, &funding_inputs).await;

    // kick-off 2
    let (kick_off_2_tx, kick_off_2_txid) = create_and_mine_kick_off_2_tx(
        &client,
        &operator_context,
        &kick_off_2_funding_utxo_address,
        kick_off_2_input_amount,
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
    let mut assert = AssertTransaction::new(&operator_context, assert_input_0);

    let secret_nonces_0 = assert.push_nonces(&verifier_0_context);
    let secret_nonces_1 = assert.push_nonces(&verifier_1_context);

    assert.pre_sign(&verifier_0_context, &secret_nonces_0);
    assert.pre_sign(&verifier_1_context, &secret_nonces_1);

    let assert_tx = assert.finalize();
    let assert_txid = assert_tx.compute_txid();
    let assert_result = client.esplora.broadcast(&assert_tx).await;
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
        &operator_context,
        disprove_input_0,
        disprove_input_1,
        script_index,
    );

    let secret_nonces_0 = disprove.push_nonces(&verifier_0_context);
    let secret_nonces_1 = disprove.push_nonces(&verifier_1_context);

    disprove.pre_sign(&verifier_0_context, &secret_nonces_0);
    disprove.pre_sign(&verifier_1_context, &secret_nonces_1);

    let reward_address = generate_pay_to_pubkey_script_address(
        withdrawer_context.network,
        &withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove.add_input_output(script_index, verifier_reward_script);

    let disprove_tx = disprove.finalize();
    let disprove_txid = disprove_tx.compute_txid();

    // mine disprove
    let disprove_result = client.esplora.broadcast(&disprove_tx).await;
    assert!(disprove_result.is_ok());

    // reward balance
    let reward_utxos = client
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
