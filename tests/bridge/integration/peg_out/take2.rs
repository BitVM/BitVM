use std::time::Duration;

use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        take2::Take2Transaction,
    },
};
use tokio::time::sleep;

use crate::bridge::{
    helper::verify_funding_inputs, integration::peg_out::utils::create_and_mine_assert_tx,
    setup::setup_test,
};

use super::utils::create_and_mine_peg_in_confirm_tx;

#[tokio::test]
async fn test_take2_success() {
    let (
        client,
        depositor_context,
        operator_context,
        verifier_context,
        _,
        _,
        connector_b,
        _,
        connector_z,
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
    let (peg_in_confirm_tx, peg_in_confirm_tx_id) = create_and_mine_peg_in_confirm_tx(
        &client,
        &depositor_context,
        &verifier_context,
        &depositor_evm_address,
        &peg_in_confirm_funding_address,
        deposit_input_amount,
    )
    .await;

    // assert
    let (assert_tx, assert_tx_id) = create_and_mine_assert_tx(
        &client,
        &operator_context,
        &verifier_context,
        &assert_funding_address,
        assert_input_amount,
    )
    .await;

    // take2
    let connector_0_input = Input {
        outpoint: OutPoint {
            txid: peg_in_confirm_tx_id,
            vout: 0,
        },
        amount: peg_in_confirm_tx.output[0].value,
    };
    let connector_2_input = Input {
        outpoint: OutPoint {
            txid: assert_tx_id,
            vout: 0,
        },
        amount: assert_tx.output[0].value,
    };
    let connector_3_input = Input {
        outpoint: OutPoint {
            txid: assert_tx_id,
            vout: 1,
        },
        amount: assert_tx.output[1].value,
    };

    let mut take2 = Take2Transaction::new(
        &operator_context,
        connector_0_input,
        connector_2_input,
        connector_3_input,
    );

    take2.pre_sign(&verifier_context);
    let take2_tx = take2.finalize();
    let take2_tx_id = take2_tx.compute_txid();

    // mine take2
    sleep(Duration::from_secs(60)).await;
    let take2_result = client.esplora.broadcast(&take2_tx).await;
    assert!(take2_result.is_ok());

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
        .find(|x| x.txid == take2_tx_id);

    // assert
    assert!(operator_utxo.is_some());
}
