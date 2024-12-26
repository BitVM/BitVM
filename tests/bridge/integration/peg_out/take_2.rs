use bitcoin::{Address, Amount, OutPoint};
use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::base::DUST_AMOUNT,
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{
            BaseTransaction, Input, MIN_RELAY_FEE_ASSERT, MIN_RELAY_FEE_PEG_IN_CONFIRM,
            MIN_RELAY_FEE_TAKE_2,
        },
        pre_signed_musig2::PreSignedMusig2Transaction,
        take_2::Take2Transaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, get_reward_amount, verify_funding_inputs, wait_timelock_expiry},
    integration::peg_out::utils::{create_and_mine_assert_tx, create_and_mine_peg_in_confirm_tx},
    setup::{setup_test, INITIAL_AMOUNT, ONE_HUNDRED},
};

#[tokio::test]
async fn test_take_2_success() {
    let config: crate::bridge::setup::SetupConfig = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let deposit_input_amount = Amount::from_sat(INITIAL_AMOUNT + MIN_RELAY_FEE_PEG_IN_CONFIRM);
    let peg_in_confirm_funding_address = config.connector_z.generate_taproot_address();
    funding_inputs.push((&peg_in_confirm_funding_address, deposit_input_amount));

    let reward_amount = get_reward_amount(ONE_HUNDRED);
    let assert_input_amount = Amount::from_sat(
        reward_amount + MIN_RELAY_FEE_ASSERT + DUST_AMOUNT * 2 + MIN_RELAY_FEE_TAKE_2,
    );
    let assert_funding_address = config.connector_b.generate_taproot_address();
    funding_inputs.push((&assert_funding_address, assert_input_amount));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    // peg-in confirm
    let (peg_in_confirm_tx, peg_in_confirm_txid) = create_and_mine_peg_in_confirm_tx(
        &config.client_0,
        &config.depositor_context,
        &config.verifier_0_context,
        &config.verifier_1_context,
        &config.connector_0,
        &config.connector_z,
        &peg_in_confirm_funding_address,
        deposit_input_amount,
    )
    .await;

    // assert
    let (assert_tx, assert_txid) = create_and_mine_assert_tx(
        &config.client_0,
        &config.verifier_0_context,
        &config.verifier_1_context,
        &assert_funding_address,
        &config.connector_4,
        &config.connector_5,
        &config.connector_b,
        &config.connector_c,
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
        &config.operator_context,
        &config.connector_0,
        &config.connector_4,
        &config.connector_5,
        &config.connector_c,
        take_2_input_0,
        take_2_input_1,
        take_2_input_2,
        take_2_input_3,
    );

    let secret_nonces_0 = take_2.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = take_2.push_nonces(&config.verifier_1_context);

    take_2.pre_sign(
        &config.verifier_0_context,
        &config.connector_0,
        &config.connector_5,
        &secret_nonces_0,
    );
    take_2.pre_sign(
        &config.verifier_1_context,
        &config.connector_0,
        &config.connector_5,
        &secret_nonces_1,
    );

    take_2.sign(&config.operator_context, &config.connector_c);

    let take_2_tx = take_2.finalize();
    let take_2_txid = take_2_tx.compute_txid();

    // mine take 2
    check_tx_output_sum(INITIAL_AMOUNT + reward_amount + DUST_AMOUNT * 2, &take_2_tx);
    println!(
        ">>>>>> MINE TAKE 2 input 0 amount: {:?}, input 1 amount: {:?}, input 2 amount: {:?}, input 3 amount: {:?}, virtual size: {:?}, outputs: {:?}",
        peg_in_confirm_tx.output[0].value,
        assert_tx.output[0].value,
        assert_tx.output[1].value,
        assert_tx.output[2].value,
        take_2_tx.vsize(),
        take_2_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .collect::<Vec<u64>>(),
    );
    println!(
        ">>>>>> TAKE 2 TX OUTPUTS SIZE: {:?}",
        take_2_tx
            .output
            .iter()
            .map(|o| o.size())
            .collect::<Vec<usize>>()
    );
    wait_timelock_expiry(config.network, Some("assert connector 4")).await;
    let take_2_result = config.client_0.esplora.broadcast(&take_2_tx).await;
    println!("Broadcast result: {:?}\n", take_2_result);
    assert!(take_2_result.is_ok());

    // operator balance
    let operator_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );
    let operator_utxos = config
        .client_0
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
