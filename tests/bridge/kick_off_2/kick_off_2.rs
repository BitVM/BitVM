use bitcoin::Amount;

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::{base::DUST_AMOUNT, peg_out::CommitmentMessageId},
    superblock::{get_superblock_hash_message, get_superblock_message},
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_KICK_OFF_2},
        kick_off_2::KickOff2Transaction,
        signing_winternitz::WinternitzSigningInputs,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::generate_stub_outpoint,
    setup::setup_test,
};
use crate::bridge::{
    helper::{check_tx_output_sum, get_reward_amount, get_superblock_header, wait_timelock_expiry},
    setup::ONE_HUNDRED,
};

#[tokio::test]
async fn test_kick_off_2_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let reward_amount = get_reward_amount(ONE_HUNDRED);
    let input_value0 = Amount::from_sat(reward_amount + MIN_RELAY_FEE_KICK_OFF_2 + DUST_AMOUNT);
    let funding_utxo_address0: bitcoin::Address = config.connector_1.generate_taproot_address();
    faucet
        .fund_input(&funding_utxo_address0, input_value0)
        .await
        .wait()
        .await;

    let funding_outpoint0 =
        generate_stub_outpoint(&config.client_0, &funding_utxo_address0, input_value0).await;

    let mut kick_off_2_tx = KickOff2Transaction::new(
        &config.operator_context,
        &config.connector_1,
        Input {
            outpoint: funding_outpoint0,
            amount: input_value0,
        },
    );

    let superblock_header = get_superblock_header();
    kick_off_2_tx.sign(
        &config.operator_context,
        &config.connector_1,
        &WinternitzSigningInputs {
            message: &get_superblock_message(&superblock_header),
            signing_key: &config.commitment_secrets[&CommitmentMessageId::Superblock],
        },
        &WinternitzSigningInputs {
            message: &get_superblock_hash_message(&superblock_header),
            signing_key: &config.commitment_secrets[&CommitmentMessageId::SuperblockHash],
        },
    );

    let tx = kick_off_2_tx.finalize();
    check_tx_output_sum(reward_amount + DUST_AMOUNT, &tx);
    println!(
        ">>>>>> MINE KICK OFF 2 TX input 0 amount: {:?}, virtual size: {:?}, output 0: {:?}, output 1: {:?}",
        input_value0,
        tx.vsize(),
        tx.output[0].value.to_sat(),
        tx.output[1].value.to_sat(),
    );
    println!(
        ">>>>>> KICK OFF 2 TX OUTPUTS SIZE: {:?}",
        tx.output.iter().map(|o| o.size()).collect::<Vec<usize>>()
    );
    wait_timelock_expiry(config.network, Some("kick off 2 connector 3")).await;
    let result: Result<(), esplora_client::Error> = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Kick Off 2 tx result: {:?}\n", result);
    assert!(result.is_ok());
}
