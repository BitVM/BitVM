use std::time::Duration;

use bitcoin::OutPoint;
use bitvm::bridge::{
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        take1::Take1Transaction,
    },
};
use tokio::time::sleep;

use crate::bridge::setup::setup_test;

use super::utils::{create_and_mine_kick_off_tx, create_and_mine_peg_in_confirm_tx};

#[tokio::test]
async fn test_take1_success() {
    let (
        client,
        depositor_context,
        operator_context,
        verifier_context,
        _,
        _,
        _,
        _,
        connector_z,
        _,
        _,
        _,
        _,
        evm_address,
    ) = setup_test();

    // peg-in confirm
    let (peg_in_confirm_tx, peg_in_confirm_tx_id) = create_and_mine_peg_in_confirm_tx(
        &client,
        &depositor_context,
        &verifier_context,
        &connector_z,
        &evm_address,
    )
    .await;

    // kick-off
    let (kick_off_tx, kick_off_tx_id) =
        create_and_mine_kick_off_tx(&client, &operator_context).await;

    // take1
    let connector_0_input = Input {
        outpoint: OutPoint {
            txid: peg_in_confirm_tx_id,
            vout: 0,
        },
        amount: peg_in_confirm_tx.output[0].value,
    };
    let connector_1_input = Input {
        outpoint: OutPoint {
            txid: kick_off_tx_id,
            vout: 0,
        },
        amount: kick_off_tx.output[0].value,
    };
    let connector_a_input = Input {
        outpoint: OutPoint {
            txid: kick_off_tx_id,
            vout: 1,
        },
        amount: kick_off_tx.output[1].value,
    };
    let connector_b_input = Input {
        outpoint: OutPoint {
            txid: kick_off_tx_id,
            vout: 2,
        },
        amount: kick_off_tx.output[2].value,
    };

    let mut take1 = Take1Transaction::new(
        &operator_context,
        connector_0_input,
        connector_1_input,
        connector_a_input,
        connector_b_input,
    );

    take1.pre_sign(&verifier_context);
    let take1_tx = take1.finalize();
    let take1_tx_id = take1_tx.compute_txid();

    // mine take1
    sleep(Duration::from_secs(60)).await;
    let take1_result = client.esplora.broadcast(&take1_tx).await;
    assert!(take1_result.is_ok());

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
        .find(|x| x.txid == take1_tx_id);

    // assert
    assert!(operator_utxo.is_some());
}
