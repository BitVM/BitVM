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

use crate::bridge::{helper::verify_funding_inputs, setup::setup_test};

use super::utils::create_and_mine_kick_off_tx;

#[tokio::test]
async fn test_disprove_success() {
    let (
        client,
        _,
        operator_context,
        verifier_context,
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
    ) = setup_test().await;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let kick_off_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    funding_inputs.push((&kick_off_funding_utxo_address, kick_off_input_amount));

    verify_funding_inputs(&client, &funding_inputs).await;

    // kick-off
    let (kick_off_tx, kick_off_tx_id) = create_and_mine_kick_off_tx(
        &client,
        &operator_context,
        &kick_off_funding_utxo_address,
        kick_off_input_amount,
    )
    .await;

    // assert
    let assert_kick_off_outpoint = OutPoint {
        txid: kick_off_tx_id,
        vout: 2, // connectorB
    };
    let assert_kick_off_input = Input {
        outpoint: assert_kick_off_outpoint,
        amount: kick_off_tx.output[2].value,
    };
    let mut assert = AssertTransaction::new(&operator_context, assert_kick_off_input);
    assert.pre_sign(&verifier_context);
    let assert_tx = assert.finalize();
    let assert_tx_id = assert_tx.compute_txid();
    let assert_result = client.esplora.broadcast(&assert_tx).await;
    assert!(assert_result.is_ok());

    // disprove
    let script_index = 1;
    let disprove_assert_outpoint_0 = OutPoint {
        txid: assert_tx_id,
        vout: 1,
    };
    let disprove_assert_input_0 = Input {
        outpoint: disprove_assert_outpoint_0,
        amount: assert_tx.output[1].value,
    };
    let disprove_assert_outpoint_1 = OutPoint {
        txid: assert_tx_id,
        vout: 2,
    };
    let disprove_assert_input_1 = Input {
        outpoint: disprove_assert_outpoint_1,
        amount: assert_tx.output[2].value,
    };

    let mut disprove = DisproveTransaction::new(
        &operator_context,
        disprove_assert_input_0,
        disprove_assert_input_1,
        script_index,
    );
    disprove.pre_sign(&verifier_context);

    let reward_address = generate_pay_to_pubkey_script_address(
        withdrawer_context.network,
        &withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove.add_input_output(script_index, verifier_reward_script);

    let disprove_tx = disprove.finalize();
    let disprove_tx_id = disprove_tx.compute_txid();

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
        .find(|x| x.txid == disprove_tx_id);

    // assert
    assert!(reward_utxo.is_some());
    assert_eq!(reward_utxo.unwrap().value, disprove_tx.output[1].value);
}
