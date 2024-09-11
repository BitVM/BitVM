use std::time::Duration;

use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        take_2::Take2Transaction,
    },
};
use tokio::time::sleep;

use crate::bridge::{
    helper::verify_funding_inputs,
    integration::peg_out::utils::{create_and_mine_assert_tx, create_and_mine_peg_in_confirm_tx},
    setup::setup_test,
};

#[tokio::test]
async fn test_take_2_success() {
    let (
        client,
        _,
        depositor_context,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        connector_b,
        _,
        connector_z,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test().await;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let deposit_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let peg_in_confirm_funding_address = connector_z.generate_taproot_address();
    funding_inputs.push((&peg_in_confirm_funding_address, deposit_input_amount));

    let assert_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let assert_funding_address = connector_b.generate_taproot_address();
    funding_inputs.push((&assert_funding_address, assert_input_amount));

    verify_funding_inputs(&client, &funding_inputs).await;

    // peg-in confirm
    let (peg_in_confirm_tx, peg_in_confirm_txid) = create_and_mine_peg_in_confirm_tx(
        &client,
        &depositor_context,
        &verifier_0_context,
        &verifier_1_context,
        &depositor_evm_address,
        &peg_in_confirm_funding_address,
        deposit_input_amount,
    )
    .await;

    // assert
    let (assert_tx, assert_txid) = create_and_mine_assert_tx(
        &client,
        &operator_context,
        &verifier_0_context,
        &verifier_1_context,
        &assert_funding_address,
        assert_input_amount,
    )
    .await;

    // take 2
    let vout = 0; // connector 0
    let take_2_input_0 = Input {
        outpoint: OutPoint {
            txid: peg_in_confirm_txid,
            vout,
        },
        amount: peg_in_confirm_tx.output[vout as usize].value,
    };
    let vout = 0; // connector 4
    let take_2_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };
    let vout = 1; // connector 5
    let take_2_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };
    let vout = 2; // connector c
    let take_2_input_3 = Input {
        outpoint: OutPoint {
            txid: assert_txid,
            vout,
        },
        amount: assert_tx.output[vout as usize].value,
    };

    let mut take_2 = Take2Transaction::new(
        &operator_context,
        take_2_input_0,
        take_2_input_1,
        take_2_input_2,
        take_2_input_3,
    );

    let secret_nonces_0 = take_2.push_nonces(&verifier_0_context);
    let secret_nonces_1 = take_2.push_nonces(&verifier_1_context);

    take_2.pre_sign(&verifier_0_context, &secret_nonces_0);
    take_2.pre_sign(&verifier_1_context, &secret_nonces_1);

    let take_2_tx = take_2.finalize();
    let take_2_txid = take_2_tx.compute_txid();

    // mine take 2
    sleep(Duration::from_secs(60)).await;
    let take_2_result = client.esplora.broadcast(&take_2_tx).await;
    assert!(take_2_result.is_ok());

    // operator balance
    let operator_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    let operator_utxos = client
        .esplora
        .get_address_utxo(operator_address.clone())
        .await
        .unwrap();
    let operator_utxo = operator_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == take_2_txid);

    // assert
    assert!(operator_utxo.is_some());
}
