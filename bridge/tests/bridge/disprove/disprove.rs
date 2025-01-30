use bitcoin::{key::Keypair, Amount, PrivateKey, PublicKey, TxOut};

use bridge::{
    connectors::base::TaprootConnector,
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_DISPROVE},
        disprove::DisproveTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};
use secp256k1::SECP256K1;

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, generate_stub_outpoint},
    setup::{setup_test_full, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_disprove_tx_success() {
    let config = setup_test_full().await;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount_0 = Amount::from_sat(MIN_RELAY_FEE_DISPROVE);
    let connector_5_address = config.connector_5.generate_taproot_address();
    faucet.fund_input(&connector_5_address, amount_0).await;

    let amount_1 = Amount::from_sat(INITIAL_AMOUNT);
    let connector_c_address = config.connector_c.generate_taproot_address();
    faucet
        .fund_input(&connector_c_address, amount_1)
        .await
        .wait()
        .await;

    let outpoint_0 = generate_stub_outpoint(&config.client_0, &connector_5_address, amount_0).await;
    let outpoint_1 = generate_stub_outpoint(&config.client_0, &connector_c_address, amount_1).await;

    let mut disprove_tx = DisproveTransaction::new(
        &config.operator_context,
        &config.connector_5,
        &config.connector_c,
        Input {
            outpoint: outpoint_0,
            amount: amount_0,
        },
        Input {
            outpoint: outpoint_1,
            amount: amount_1,
        },
        1,
    );

    let secret_nonces_0 = disprove_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_tx.push_nonces(&config.verifier_1_context);

    disprove_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_5,
        &secret_nonces_0,
    );
    disprove_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_5,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove_tx.add_input_output(&config.connector_c, 1, vec![], verifier_reward_script);

    let tx = disprove_tx.finalize();
    check_tx_output_sum(INITIAL_AMOUNT, &tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Disprove tx result: {:?}\n", result);
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_disprove_tx_with_verifier_added_to_output_success() {
    let config = setup_test_full().await;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount_0 = Amount::from_sat(MIN_RELAY_FEE_DISPROVE);
    let connector_5_address = config.connector_5.generate_taproot_address();
    faucet.fund_input(&connector_5_address, amount_0).await;

    let amount_1 = Amount::from_sat(INITIAL_AMOUNT);
    let connector_c_address = config.connector_c.generate_taproot_address();
    faucet
        .fund_input(&connector_c_address, amount_1)
        .await
        .wait()
        .await;

    let outpoint_0 = generate_stub_outpoint(&config.client_0, &connector_5_address, amount_0).await;
    let outpoint_1 = generate_stub_outpoint(&config.client_0, &connector_c_address, amount_1).await;

    let mut disprove_tx = DisproveTransaction::new(
        &config.operator_context,
        &config.connector_5,
        &config.connector_c,
        Input {
            outpoint: outpoint_0,
            amount: amount_0,
        },
        Input {
            outpoint: outpoint_1,
            amount: amount_1,
        },
        1,
    );

    let secret_nonces_0 = disprove_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_tx.push_nonces(&config.verifier_1_context);

    disprove_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_5,
        &secret_nonces_0,
    );
    disprove_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_5,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove_tx.add_input_output(&config.connector_c, 1, vec![], verifier_reward_script);

    let mut tx = disprove_tx.finalize();

    let verifier_secret: &str = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
    let verifier_keypair = Keypair::from_seckey_str_global(verifier_secret).unwrap();
    let verifier_private_key = PrivateKey::new(
        verifier_keypair.secret_key(),
        config.verifier_0_context.network,
    );
    let verifier_pubkey = PublicKey::from_private_key(SECP256K1, &verifier_private_key);
    let verifier_pubkey_script = generate_pay_to_pubkey_script(&verifier_pubkey);
    let verifier_output_dust = verifier_pubkey_script.minimal_non_dust().to_sat();

    let verifier_output = TxOut {
        value: Amount::from_sat(verifier_output_dust),
        script_pubkey: verifier_pubkey_script,
    };

    // the output dust is taken from reward_output_amount
    // output 1 is not part of pre-signing, it will not trigger "Invalid Schnorr signature" error
    tx.output[1].value -= verifier_output.value;
    tx.output.push(verifier_output);
    check_tx_output_sum(INITIAL_AMOUNT, &tx);

    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Disprove tx result: {:?}\n", result);
    assert!(result.is_ok());
}
