use bitcoin::{Address, Amount};

use bitvm::bridge::{
    connectors::base::{P2wshConnector, TaprootConnector},
    graphs::base::DUST_AMOUNT,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_TAKE_1},
        pre_signed_musig2::PreSignedMusig2Transaction,
        take_1::Take1Transaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{
        check_tx_output_sum, generate_stub_outpoint, get_reward_amount, wait_timelock_expiry,
    },
    setup::{setup_test, ONE_HUNDRED},
};

#[tokio::test]
async fn test_take_1_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let input_value0 = Amount::from_sat(ONE_HUNDRED + MIN_RELAY_FEE_TAKE_1);
    let funding_utxo_address0 = config.connector_0.generate_taproot_address();
    funding_inputs.push((&funding_utxo_address0, input_value0));
    let input_value1 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address1 = config.connector_a.generate_taproot_address();
    funding_inputs.push((&funding_utxo_address1, input_value1));
    let input_value2 = Amount::from_sat(DUST_AMOUNT);
    let funding_utxo_address2 = config.connector_3.generate_address();
    funding_inputs.push((&funding_utxo_address2, input_value2));
    let reward_amount = get_reward_amount(ONE_HUNDRED);
    let input_value3 = Amount::from_sat(reward_amount);
    let funding_utxo_address3 = config.connector_b.generate_taproot_address();
    funding_inputs.push((&funding_utxo_address3, input_value3));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    let funding_outpoint0 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address0, input_value0).await;
    let funding_outpoint1 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address1, input_value1).await;
    let funding_outpoint2 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address2, input_value2).await;
    let funding_outpoint3 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address3, input_value3).await;

    let mut take_1_tx = Take1Transaction::new(
        &config.operator_context,
        &config.connector_0,
        &config.connector_3,
        &config.connector_a,
        &config.connector_b,
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
        Input {
            outpoint: funding_outpoint3,
            amount: input_value3,
        },
    );

    let secret_nonces_0 = take_1_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = take_1_tx.push_nonces(&config.verifier_1_context);

    take_1_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_0,
        &config.connector_b,
        &secret_nonces_0,
    );
    take_1_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_0,
        &config.connector_b,
        &secret_nonces_1,
    );

    let tx = take_1_tx.finalize();
    check_tx_output_sum(ONE_HUNDRED + reward_amount + DUST_AMOUNT * 2, &tx);
    wait_timelock_expiry(config.network, Some("kick off 2 connector 3")).await;
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Take 1 tx result: {:?}\n", result);
    assert!(result.is_ok());
}
