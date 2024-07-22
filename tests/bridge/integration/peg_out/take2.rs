use std::time::Duration;

use bitcoin::OutPoint;
use bitvm::bridge::{
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        take2::Take2Transaction,
    },
};
use tokio::time::sleep;

use crate::bridge::{integration::peg_out::utils::create_and_mine_assert_tx, setup::setup_test};

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
        evm_address,
    ) = setup_test().await;

    // peg-in confirm
    let (peg_in_confirm_tx, peg_in_confirm_tx_id) = create_and_mine_peg_in_confirm_tx(
        &client,
        &depositor_context,
        &verifier_context,
        &connector_z,
        &evm_address,
    )
    .await;

    // assert
    let (assert_tx, assert_tx_id) =
        create_and_mine_assert_tx(&client, &operator_context, &verifier_context, &connector_b)
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
