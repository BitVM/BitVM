use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_KICK_OFF_TIMEOUT},
        kick_off_timeout::KickOffTimeoutTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
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
async fn test_kick_off_timeout_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let reward_amount = get_reward_amount(ONE_HUNDRED);
    let input_value0 = Amount::from_sat(reward_amount + MIN_RELAY_FEE_KICK_OFF_TIMEOUT);
    faucet
        .fund_input(&config.connector_1.generate_taproot_address(), input_value0)
        .await
        .wait()
        .await;
    let outpoint_0 = generate_stub_outpoint(
        &config.client_0,
        &config.connector_1.generate_taproot_address(),
        input_value0,
    )
    .await;

    let mut kick_off_timeout_tx = KickOffTimeoutTransaction::new(
        &config.operator_context,
        &config.connector_1,
        Input {
            outpoint: outpoint_0,
            amount: input_value0,
        },
    );

    let secret_nonces_0 = kick_off_timeout_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = kick_off_timeout_tx.push_nonces(&config.verifier_1_context);

    kick_off_timeout_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_1,
        &secret_nonces_0,
    );
    kick_off_timeout_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_1,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    kick_off_timeout_tx.add_output(reward_address.script_pubkey());

    let tx = kick_off_timeout_tx.finalize();
    check_tx_output_sum(reward_amount, &tx);
    println!("Script Path Spend Transaction: {:?}\n", tx);
    println!(
        ">>>>>> MINE KICK OFF TIMEOUT TX input 0 amount: {:?}, virtual size: {:?}, output 0: {:?}, output 1: {:?}",
        input_value0,
        tx.vsize(),
        tx.output[0].value.to_sat(),
        tx.output[1].value.to_sat(),
    );
    println!(
        ">>>>>> KICK OFF TIMEOUT TX OUTPUTS SIZE: {:?}",
        tx.output.iter().map(|o| o.size()).collect::<Vec<usize>>()
    );
    wait_timelock_expiry(config.network, Some("kick off 1 connector 1")).await;
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
