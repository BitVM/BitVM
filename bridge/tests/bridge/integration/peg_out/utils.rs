use std::collections::HashMap;

use bitcoin::{Address, Amount, Transaction, Txid};
use bitvm::signatures::signing_winternitz::{WinternitzSecret, WinternitzSigningInputs};
use bridge::{
    client::client::BitVMClient,
    commitments::CommitmentMessageId,
    connectors::{
        connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
        connector_4::Connector4, connector_5::Connector5, connector_6::Connector6,
        connector_b::ConnectorB, connector_c::ConnectorC, connector_z::ConnectorZ,
    },
    contexts::{depositor::DepositorContext, operator::OperatorContext, verifier::VerifierContext},
    superblock::{get_superblock_hash_message, get_superblock_message},
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
        kick_off_1::KickOff1Transaction,
        kick_off_2::KickOff2Transaction,
        peg_in_confirm::PegInConfirmTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use crate::bridge::helper::{generate_stub_outpoint, get_superblock_header, wait_timelock_expiry};

pub async fn create_and_mine_kick_off_1_tx(
    client: &BitVMClient,
    operator_context: &OperatorContext,
    kick_off_1_funding_utxo_address: &Address,
    connector_1: &Connector1,
    connector_2: &Connector2,
    connector_6: &Connector6,
    input_amount: Amount,
    commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
) -> (Transaction, Txid) {
    let kick_off_1_funding_outpoint =
        generate_stub_outpoint(client, kick_off_1_funding_utxo_address, input_amount).await;
    let kick_off_1_input = Input {
        outpoint: kick_off_1_funding_outpoint,
        amount: input_amount,
    };
    let mut kick_off_1 = KickOff1Transaction::new(
        operator_context,
        connector_1,
        connector_2,
        connector_6,
        kick_off_1_input,
    );

    let ethereum_txid = "8b274fbb76c72f66c467c976c61d5ac212620e036818b5986a33f7b557cb2de8";
    let bitcoin_txid = "8b4cce4a1a9522392c095df6416533d89e1e6ac7bdf8ab3c1685426b321ed182";
    let source_network_txid_digits = WinternitzSigningInputs {
        message: bitcoin_txid.as_bytes(),
        signing_key: &commitment_secrets[&CommitmentMessageId::PegOutTxIdSourceNetwork],
    };
    let destination_network_txid_digits = WinternitzSigningInputs {
        message: ethereum_txid.as_bytes(),
        signing_key: &commitment_secrets[&CommitmentMessageId::PegOutTxIdDestinationNetwork],
    };
    kick_off_1.sign(
        operator_context,
        connector_6,
        &source_network_txid_digits,
        &destination_network_txid_digits,
    );

    let kick_off_1_tx = kick_off_1.finalize();
    let kick_off_1_txid = kick_off_1_tx.compute_txid();

    // mine kick-off 1 tx
    let kick_off_1_result = client.esplora.broadcast(&kick_off_1_tx).await;
    println!("Kick-off 1 result: {kick_off_1_result:?}");
    assert!(kick_off_1_result.is_ok());

    (kick_off_1_tx, kick_off_1_txid)
}

pub async fn create_and_mine_kick_off_2_tx(
    client: &BitVMClient,
    operator_context: &OperatorContext,
    connector_1: &Connector1,
    connector_b: &ConnectorB,
    kick_off_2_funding_utxo_address: &Address,
    input_amount: Amount,
    commitment_secrets: &HashMap<CommitmentMessageId, WinternitzSecret>,
) -> (Transaction, Txid) {
    let kick_off_2_funding_outpoint =
        generate_stub_outpoint(client, kick_off_2_funding_utxo_address, input_amount).await;
    let kick_off_2_input = Input {
        outpoint: kick_off_2_funding_outpoint,
        amount: input_amount,
    };
    let mut kick_off_2 = KickOff2Transaction::new(
        operator_context,
        connector_1,
        connector_b,
        kick_off_2_input,
    );
    let superblock_header = get_superblock_header();
    kick_off_2.sign(
        operator_context,
        connector_1,
        &WinternitzSigningInputs {
            message: &get_superblock_message(&superblock_header),
            signing_key: &commitment_secrets[&CommitmentMessageId::Superblock],
        },
        &WinternitzSigningInputs {
            message: &get_superblock_hash_message(&superblock_header),
            signing_key: &commitment_secrets[&CommitmentMessageId::SuperblockHash],
        },
    );
    let kick_off_2_tx = kick_off_2.finalize();
    let kick_off_2_txid = kick_off_2_tx.compute_txid();

    // mine kick-off 2 tx
    wait_timelock_expiry(operator_context.network, Some("kick off 1 connector 1")).await;
    let kick_off_2_result = client.esplora.broadcast(&kick_off_2_tx).await;
    println!("Kick off 2 tx result: {kick_off_2_result:?}");
    assert!(kick_off_2_result.is_ok());

    (kick_off_2_tx, kick_off_2_txid)
}

pub async fn create_and_mine_assert_tx(
    client: &BitVMClient,
    verifier_0_context: &VerifierContext,
    verifier_1_context: &VerifierContext,
    assert_funding_utxo_address: &Address,
    connector_4: &Connector4,
    connector_5: &Connector5,
    connector_b: &ConnectorB,
    connector_c: &ConnectorC,
    input_amount: Amount,
) -> (Transaction, Txid) {
    // create assert tx
    let assert_funding_outpoint =
        generate_stub_outpoint(client, assert_funding_utxo_address, input_amount).await;
    let assert_input = Input {
        outpoint: assert_funding_outpoint,
        amount: input_amount,
    };
    let mut assert = AssertTransaction::new(
        connector_4,
        connector_5,
        connector_b,
        connector_c,
        assert_input,
    );

    let secret_nonces_0 = assert.push_nonces(verifier_0_context);
    let secret_nonces_1 = assert.push_nonces(verifier_1_context);

    assert.pre_sign(verifier_0_context, connector_b, &secret_nonces_0);
    assert.pre_sign(verifier_1_context, connector_b, &secret_nonces_1);

    let assert_tx = assert.finalize();
    let assert_txid = assert_tx.compute_txid();

    // mine assert tx
    wait_timelock_expiry(verifier_0_context.network, Some("kick off 2 connector b")).await;
    let assert_result = client.esplora.broadcast(&assert_tx).await;
    assert!(assert_result.is_ok());

    (assert_tx, assert_txid)
}

pub async fn create_and_mine_peg_in_confirm_tx(
    client: &BitVMClient,
    depositor_context: &DepositorContext,
    verifier_0_context: &VerifierContext,
    verifier_1_context: &VerifierContext,
    connector_0: &Connector0,
    connector_z: &ConnectorZ,
    funding_address: &Address,
    input_amount: Amount,
) -> (Transaction, Txid) {
    let peg_in_confirm_funding_outpoint =
        generate_stub_outpoint(client, funding_address, input_amount).await;

    let confirm_input = Input {
        outpoint: peg_in_confirm_funding_outpoint,
        amount: input_amount,
    };
    let mut peg_in_confirm =
        PegInConfirmTransaction::new(depositor_context, connector_0, connector_z, confirm_input);

    let secret_nonces_0 = peg_in_confirm.push_nonces(verifier_0_context);
    let secret_nonces_1 = peg_in_confirm.push_nonces(verifier_1_context);

    peg_in_confirm.pre_sign(verifier_0_context, connector_z, &secret_nonces_0);
    peg_in_confirm.pre_sign(verifier_1_context, connector_z, &secret_nonces_1);

    let peg_in_confirm_tx = peg_in_confirm.finalize();
    let peg_in_confirm_txid = peg_in_confirm_tx.compute_txid();

    // mine peg-in confirm
    let confirm_result = client.esplora.broadcast(&peg_in_confirm_tx).await;
    assert!(confirm_result.is_ok());

    (peg_in_confirm_tx, peg_in_confirm_txid)
}
