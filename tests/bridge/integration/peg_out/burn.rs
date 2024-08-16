use std::time::Duration;

use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        burn::BurnTransaction,
    },
};
use tokio::time::sleep;

use crate::bridge::{helper::verify_funding_inputs, setup::setup_test};

use super::utils::create_and_mine_kick_off_tx;

#[tokio::test]
async fn test_burn_success() {
    let (
        client,
        _,
        _,
        operator_context,
        verifier0_context,
        verifier1_context,
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

    // burn
    let burn_kick_off_outpoint = OutPoint {
        txid: kick_off_tx_id,
        vout: 2,
    };
    let burn_kick_off_input = Input {
        outpoint: burn_kick_off_outpoint,
        amount: kick_off_tx.output[2].value,
    };

    let mut burn = BurnTransaction::new(&operator_context, burn_kick_off_input);

    let secret_nonces0 = burn.push_nonces(&verifier0_context);
    let secret_nonces1 = burn.push_nonces(&verifier1_context);

    burn.pre_sign(&verifier0_context, &secret_nonces0);
    burn.pre_sign(&verifier1_context, &secret_nonces1);

    let reward_address = generate_pay_to_pubkey_script_address(
        withdrawer_context.network,
        &withdrawer_context.withdrawer_public_key,
    );
    burn.add_output(reward_address.script_pubkey());

    let burn_tx = burn.finalize();
    let burn_tx_id = burn_tx.compute_txid();

    // mine burn
    sleep(Duration::from_secs(60)).await;
    let burn_result = client.esplora.broadcast(&burn_tx).await;
    println!("Broadcast burn result: {:?}\n", burn_result);
    assert!(burn_result.is_ok());

    // reward balance
    let reward_utxos = client
        .esplora
        .get_address_utxo(reward_address)
        .await
        .unwrap();
    let reward_utxo = reward_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == burn_tx_id);

    // assert
    assert!(reward_utxo.is_some());
    assert_eq!(reward_utxo.unwrap().value, burn_tx.output[1].value);
}
