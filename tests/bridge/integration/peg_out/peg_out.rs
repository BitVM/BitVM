use bitcoin::Amount;

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        peg_out::PegOutTransaction,
    },
};

use crate::bridge::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_out_success() {
    let (
        client,
        _,
        operator_context,
        _,
        withdrawer_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        withdrawer_evm_address,
    ) = setup_test().await;
    let timestamp = 1722328130u32;

    let input_amount_raw = INITIAL_AMOUNT + FEE_AMOUNT;
    let operator_input_amount = Amount::from_sat(input_amount_raw);

    let operator_funding_utxo_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );
    println!(
        "operator_funding_utxo_address: {:?}",
        operator_funding_utxo_address
    );
    let operator_funding_outpoint = generate_stub_outpoint(
        &client,
        &operator_funding_utxo_address,
        operator_input_amount,
    )
    .await;
    println!(
        "operator_funding_utxo.txid: {:?}",
        operator_funding_outpoint.txid
    );
    let operator_input = Input {
        outpoint: operator_funding_outpoint,
        amount: operator_input_amount,
    };

    let peg_out = PegOutTransaction::new(
        &operator_context,
        &withdrawer_context.withdrawer_public_key,
        &withdrawer_evm_address,
        timestamp,
        operator_input,
    );

    let peg_out_tx = peg_out.finalize();
    let peg_out_tx_id = peg_out_tx.compute_txid();

    // mine peg-out
    let peg_out_result = client.esplora.broadcast(&peg_out_tx).await;
    println!("Peg Out Tx result: {:?}", peg_out_result);
    assert!(peg_out_result.is_ok());
    println!("Peg Out Txid: {:?}", peg_out_tx_id);
}
