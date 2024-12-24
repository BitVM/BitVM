use bitcoin::{
    consensus::encode::serialize_hex, key::Keypair, Amount, PrivateKey, PublicKey, TxOut,
};

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_DISPROVE_CHAIN},
        disprove_chain::DisproveChainTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_relay_fee, generate_stub_outpoint},
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_disprove_chain_tx_success() {
    let config = setup_test().await;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    let amount = Amount::from_sat(INITIAL_AMOUNT + MIN_RELAY_FEE_DISPROVE_CHAIN);
    faucet
        .fund_input(&config.connector_b.generate_taproot_address(), amount)
        .await
        .wait()
        .await;

    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &config.connector_b.generate_taproot_address(),
        amount,
    )
    .await;

    let mut disprove_chain_tx = DisproveChainTransaction::new(
        &config.operator_context,
        &config.connector_b,
        Input { outpoint, amount },
    );

    let secret_nonces_0 = disprove_chain_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_chain_tx.push_nonces(&config.verifier_1_context);

    disprove_chain_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    disprove_chain_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    disprove_chain_tx.add_output(reward_address.script_pubkey());

    let tx = disprove_chain_tx.finalize();
    check_relay_fee(INITIAL_AMOUNT, &tx);
    println!("Script Path Spend Transaction: {:?}\n", tx);

    println!(
        ">>>>>> MINE DISPROVE CHAIN TX input 0 amount: {:?}, virtual size: {:?}, output 0: {:?}, output 1: {:?}",
        amount,
        tx.vsize(),
        tx.output[0].value.to_sat(),
        tx.output[1].value.to_sat(),
    );
    println!(
        ">>>>>> DISPROVE CHAIN TX OUTPUTS SIZE: {:?}",
        tx.output.iter().map(|o| o.size()).collect::<Vec<usize>>()
    );
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Disprove Chain tx result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}

#[tokio::test]
//TODO: delete it after confirmation, disprove chain only needs 2 outputs
async fn test_disprove_chain_tx_with_verifier_added_to_output_success() {
    let config = setup_test().await;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    let amount = Amount::from_sat(INITIAL_AMOUNT + MIN_RELAY_FEE_DISPROVE_CHAIN);
    faucet
        .fund_input(&config.connector_b.generate_taproot_address(), amount)
        .await
        .wait()
        .await;
    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &config.connector_b.generate_taproot_address(),
        amount,
    )
    .await;

    let mut disprove_chain_tx = DisproveChainTransaction::new(
        &config.operator_context,
        &config.connector_b,
        Input { outpoint, amount },
    );

    let secret_nonces_0 = disprove_chain_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_chain_tx.push_nonces(&config.verifier_1_context);

    disprove_chain_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    disprove_chain_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    disprove_chain_tx.add_output(reward_address.script_pubkey());

    let mut tx = disprove_chain_tx.finalize();

    let secp = config.verifier_0_context.secp;
    let verifier_secret: &str = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
    let verifier_keypair = Keypair::from_seckey_str(&secp, verifier_secret).unwrap();
    let verifier_private_key = PrivateKey::new(
        verifier_keypair.secret_key(),
        config.verifier_0_context.network,
    );
    let verifier_pubkey = PublicKey::from_private_key(&secp, &verifier_private_key);
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
    check_relay_fee(INITIAL_AMOUNT, &tx);

    println!("Script Path Spend Transaction: {:?}\n", tx);

    println!(
        ">>>>>> MINE DISPROVE CHAIN TX input 0 amount: {:?}, virtual size: {:?}, output 0: {:?}, output 1: {:?}",
        amount,
        tx.vsize(),
        tx.output[0].value.to_sat(),
        tx.output[1].value.to_sat(),
    );
    println!(
        ">>>>>> DISPROVE CHAIN TX OUTPUTS SIZE: {:?}",
        tx.output.iter().map(|o| o.size()).collect::<Vec<usize>>()
    );
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Disprove Chain tx result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
