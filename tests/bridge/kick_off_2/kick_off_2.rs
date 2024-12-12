use std::str::FromStr;

use bitcoin::{
    block::{Header, Version},
    Amount, BlockHash, CompactTarget, TxMerkleNode,
};

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

use crate::bridge::faucet::{Faucet, FaucetType};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_kick_off_2_tx() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let input_value0 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
    let funding_utxo_address0 = config.connector_1.generate_taproot_address();
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

    let superblock_header = Header {
        version: Version::from_consensus(0x200d2000),
        prev_blockhash: BlockHash::from_str(
            "000000000000000000027c9f5b07f21e39ba31aa4d900d519478bdac32f4a15d",
        )
        .unwrap(),
        merkle_root: TxMerkleNode::from_str(
            "0064b0d54f20412756ba7ce07b0594f3548b06f2dad5cfeaac2aca508634ed19",
        )
        .unwrap(),
        time: 1729251961,
        bits: CompactTarget::from_hex("0x17030ecd").unwrap(),
        nonce: 0x400e345c,
    };
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
