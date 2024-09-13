use std::time::Duration;

use alloy::{primitives::Address as EvmAddress, transports::http::reqwest::Url};
use bitcoin::Amount;

use bitvm::bridge::{
    client::chain::{chain::Chain, ethereum::EthereumInitConfig},
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        base::{BaseTransaction, Input},
        peg_out::PegOutTransaction,
    },
};
use tokio::time::sleep;

use crate::bridge::{
    helper::{fund_utxo, generate_stub_outpoint},
    setup::setup_test,
};

#[tokio::test]
async fn test_peg_out_for_chain() {
    let (
        client,
        _,
        _,
        operator_context,
        _,
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
        _,
        _,
        _,
    ) = setup_test().await;
    let mut adaptors = Chain::new();
    adaptors.init_ethereum(EthereumInitConfig {
        rpc_url: "http://127.0.0.1:8545".parse::<Url>().unwrap(),
        bridge_address: "0x76d05F58D14c0838EC630C8140eDC5aB7CD159Dc"
            .parse::<EvmAddress>()
            .unwrap(),
        bridge_creation_block: 20588300,
    });
    let events_result = adaptors.get_peg_out_init().await;
    assert!(events_result.as_ref().is_ok_and(|x| x.len() > 0));

    let peg_out_event = events_result.unwrap().pop().unwrap();

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

    fund_utxo(&operator_funding_utxo_address, operator_input_amount).await;
    sleep(Duration::from_secs(5)).await;

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
        &peg_out_event.withdrawer_chain_address,
        peg_out_event.timestamp,
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
