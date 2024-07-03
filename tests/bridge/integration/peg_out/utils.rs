use bitcoin::{Amount, Transaction, Txid};
use bitvm::bridge::{
    client::BitVMClient,
    connectors::{connector::TaprootConnector, connector_b::ConnectorB, connector_z::ConnectorZ},
    contexts::{depositor::DepositorContext, operator::OperatorContext, verifier::VerifierContext},
    graph::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        assert::AssertTransaction,
        base::{BaseTransaction, Input},
        kick_off::KickOffTransaction,
        peg_in_confirm::PegInConfirmTransaction,
    },
};

use crate::bridge::helper::generate_stub_outpoint;

pub async fn create_and_mine_kick_off_tx(
    client: &BitVMClient,
    operator_context: &OperatorContext,
) -> (Transaction, Txid) {
    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT;
    let input_amount = Amount::from_sat(input_amount_raw);

    // create kick-off tx
    let kick_off_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    let kick_off_funding_outpoint =
        generate_stub_outpoint(&client, &kick_off_funding_utxo_address, input_amount).await;
    let kick_off_input = Input {
        outpoint: kick_off_funding_outpoint,
        amount: input_amount,
    };
    let kick_off = KickOffTransaction::new(&operator_context, kick_off_input);
    let kick_off_tx = kick_off.finalize();
    let kick_off_tx_id = kick_off_tx.compute_txid();

    // mine kick-off tx
    let kick_off_result = client.esplora.broadcast(&kick_off_tx).await;
    assert!(kick_off_result.is_ok());

    return (kick_off_tx, kick_off_tx_id);
}

pub async fn create_and_mine_assert_tx(
    client: &BitVMClient,
    operator_context: &OperatorContext,
    verifier_context: &VerifierContext,
    connector_b: &ConnectorB,
) -> (Transaction, Txid) {
    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT;
    let input_amount = Amount::from_sat(input_amount_raw);

    // create assert tx
    let assert_funding_outpoint = generate_stub_outpoint(
        &client,
        &connector_b.generate_taproot_address(),
        input_amount,
    )
    .await;
    let assert_input = Input {
        outpoint: assert_funding_outpoint,
        amount: input_amount,
    };
    let mut assert = AssertTransaction::new(&operator_context, assert_input);
    assert.pre_sign(&verifier_context);
    let assert_tx = assert.finalize();
    let assert_tx_id = assert_tx.compute_txid();

    // mine assert tx
    let assert_result = client.esplora.broadcast(&assert_tx).await;
    assert!(assert_result.is_ok());

    return (assert_tx, assert_tx_id);
}

pub async fn create_and_mine_peg_in_confirm_tx(
    client: &BitVMClient,
    depositor_context: &DepositorContext,
    verifier_context: &VerifierContext,
    connector_z: &ConnectorZ,
) -> (Transaction, Txid) {
    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT;
    let deposit_input_amount = Amount::from_sat(input_amount_raw);

    // create peg-in confirm tx
    let funding_address = connector_z.generate_taproot_address();
    let peg_in_confirm_funding_outpoint =
        generate_stub_outpoint(client, &funding_address, deposit_input_amount).await;

    let confirm_input = Input {
        outpoint: peg_in_confirm_funding_outpoint,
        amount: deposit_input_amount,
    };
    let mut peg_in_confirm = PegInConfirmTransaction::new(
        depositor_context,
        confirm_input,
        depositor_context.evm_address.clone(),
    );
    peg_in_confirm.pre_sign(verifier_context);
    let peg_in_confirm_tx = peg_in_confirm.finalize();
    let peg_in_confirm_tx_id = peg_in_confirm_tx.compute_txid();

    // mine peg-in confirm
    let confirm_result = client.esplora.broadcast(&peg_in_confirm_tx).await;
    assert!(confirm_result.is_ok());

    return (peg_in_confirm_tx, peg_in_confirm_tx_id);
}
