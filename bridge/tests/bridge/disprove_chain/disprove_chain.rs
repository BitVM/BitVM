use bitcoin::{Amount, Network::Regtest};

use bitvm::signatures::signing_winternitz::{generate_winternitz_witness, WinternitzSigningInputs};
use bridge::{
    commitments::CommitmentMessageId,
    connectors::base::TaprootConnector,
    scripts::generate_pay_to_pubkey_script_address,
    superblock::{get_start_time_block_number, get_superblock_hash_message},
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_DISPROVE_CHAIN},
        disprove_chain::DisproveChainTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, generate_stub_outpoint, get_superblock_header},
    setup::{setup_test, INITIAL_AMOUNT},
};

#[ignore]
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

    // TODO: setup the test headers appropriately for the verification in Disprove Chain to pass
    let committed_sb = get_superblock_header();
    let disprove_sb = get_superblock_header();

    let start_time_witness = generate_winternitz_witness(&WinternitzSigningInputs {
        message: &get_start_time_block_number(Regtest).to_le_bytes(),
        signing_key: &config.commitment_secrets[&CommitmentMessageId::StartTime],
    });

    let superblock_hash_witness = generate_winternitz_witness(&WinternitzSigningInputs {
        message: &get_superblock_hash_message(&committed_sb),
        signing_key: &config.commitment_secrets[&CommitmentMessageId::SuperblockHash],
    });

    disprove_chain_tx.sign(&disprove_sb, &start_time_witness, &superblock_hash_witness);
    let tx = disprove_chain_tx.finalize();
    check_tx_output_sum(INITIAL_AMOUNT, &tx);

    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Disprove Chain tx result: {:?}\n", result);
    assert!(result.is_ok());
}
