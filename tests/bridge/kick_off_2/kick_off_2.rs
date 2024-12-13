use bitcoin::Amount;

use bitvm::bridge::{
    connectors::base::TaprootConnector,
    graphs::{base::ONE_HUNDRED, peg_out::CommitmentMessageId},
    superblock::{get_superblock_hash_message, get_superblock_message},
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_2::KickOff2Transaction,
        signing_winternitz::WinternitzSigningInputs,
    },
};

use crate::bridge::helper::get_superblock_header;

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_kick_off_2_tx() {
    let config = setup_test().await;

    let input_value0 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo_address0 = config.connector_1.generate_taproot_address();
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
    // println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    // println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
