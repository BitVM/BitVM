use bitcoin::{consensus::encode::serialize_hex, Address, Amount};

use bitvm::bridge::{
    connectors::base::{P2wshConnector, TaprootConnector},
    graphs::base::DUST_AMOUNT,
    transactions::{
        assert_transactions::assert_final::AssertFinalTransaction,
        base::{BaseTransaction, Input, MIN_RELAY_FEE_ASSERT_FINAL},
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{
        check_tx_output_sum, generate_stub_outpoint, get_reward_amount, verify_funding_inputs,
    },
    setup::{setup_test, ONE_HUNDRED},
};

#[tokio::test]
async fn test_assert_final_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let reward_amount = get_reward_amount(ONE_HUNDRED);
    // not adding assert final relay fee since hundreds of dust will cover it
    let input_value0 = Amount::from_sat(reward_amount);
    let funding_utxo_address0 = config.connector_d.generate_taproot_address();
    funding_inputs.push((&funding_utxo_address0, input_value0));
    let assert_commit1_dust_amount =
        config.assert_commit_connectors_e_1.connectors_num() as u64 * DUST_AMOUNT;
    let input_value1 = Amount::from_sat(assert_commit1_dust_amount);
    let funding_utxo_address1 = config
        .assert_commit_connectors_f
        .connector_f_1
        .generate_address();
    funding_inputs.push((&funding_utxo_address1, input_value1));
    let assert_commit2_dust_amount =
        config.assert_commit_connectors_e_2.connectors_num() as u64 * DUST_AMOUNT;
    let input_value2 = Amount::from_sat(assert_commit2_dust_amount);
    let funding_utxo_address2 = config
        .assert_commit_connectors_f
        .connector_f_2
        .generate_address();
    funding_inputs.push((&funding_utxo_address2, input_value2));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    let funding_outpoint0 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address0, input_value0).await;
    let funding_outpoint1 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address1, input_value1).await;
    let funding_outpoint2 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address2, input_value2).await;

    let mut assert_final_tx = AssertFinalTransaction::new(
        &config.operator_context,
        &config.connector_4,
        &config.connector_5,
        &config.connector_c,
        &config.connector_d,
        &config.assert_commit_connectors_f,
        Input {
            outpoint: funding_outpoint0,
            amount: input_value0,
        },
        Input {
            outpoint: funding_outpoint1,
            amount: input_value1,
        },
        Input {
            outpoint: funding_outpoint2,
            amount: input_value2,
        },
    );

    let secret_nonces_0 = assert_final_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_final_tx.push_nonces(&config.verifier_1_context);

    assert_final_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_d,
        &secret_nonces_0,
    );
    assert_final_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_d,
        &secret_nonces_1,
    );

    let tx = assert_final_tx.finalize();
    check_tx_output_sum(
        reward_amount + assert_commit1_dust_amount + assert_commit2_dust_amount
            - MIN_RELAY_FEE_ASSERT_FINAL,
        &tx,
    );
    println!(
        ">>>>>> MINE ASSERT FINAL TX input 0 amount: {:?}, virtual size: {:?}, outputs: {:?}",
        input_value0,
        tx.vsize(),
        tx.output
            .iter()
            .map(|o| o.value.to_sat())
            .collect::<Vec<u64>>(),
    );
    println!(
        ">>>>>> ASSERT FINAL TX OUTPUTS SIZE: {:?}",
        tx.output.iter().map(|o| o.size()).collect::<Vec<usize>>()
    );
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Assert final tx result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
