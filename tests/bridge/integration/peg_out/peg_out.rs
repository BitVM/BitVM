use bitcoin::{Address, Amount};

use bitvm::bridge::{
    client::chain::chain::PegOutEvent,
    scripts::{generate_p2pkh_address, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_PEG_OUT},
        peg_out::PegOutTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, generate_stub_outpoint, verify_funding_inputs},
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_peg_out_success() {
    let config = setup_test().await;
    let timestamp = 1722328130u32;

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let operator_input_amount = Amount::from_sat(INITIAL_AMOUNT + MIN_RELAY_FEE_PEG_OUT);
    let operator_funding_utxo_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );
    funding_inputs.push((&operator_funding_utxo_address, operator_input_amount));

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    faucet
        .fund_input(&operator_funding_utxo_address, operator_input_amount)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    let operator_funding_outpoint = generate_stub_outpoint(
        &config.client_0,
        &operator_funding_utxo_address,
        operator_input_amount,
    )
    .await;
    println!(
        "operator_funding_utxo.txid: {:?}",
        operator_funding_outpoint.txid
    );
    let stub_event = PegOutEvent {
        source_outpoint: operator_funding_outpoint,
        amount: operator_input_amount,
        timestamp,
        withdrawer_chain_address: config.withdrawer_evm_address,
        withdrawer_destination_address: generate_p2pkh_address(
            config.withdrawer_context.network,
            &config.withdrawer_context.withdrawer_public_key,
        )
        .to_string(),
        withdrawer_public_key_hash: config
            .withdrawer_context
            .withdrawer_public_key
            .pubkey_hash(),
        operator_public_key: config.operator_context.operator_public_key,
        tx_hash: [0u8; 4].into(),
    };
    let input = Input {
        outpoint: operator_funding_outpoint,
        amount: operator_input_amount,
    };

    let mut peg_out = PegOutTransaction::new(&config.operator_context, &stub_event, input);

    let peg_out_tx = peg_out.finalize();
    let peg_out_txid = peg_out_tx.compute_txid();

    println!(
        ">>>>>> MINE PEG OUT TX input 0 amount: {:?}, virtual size: {:?}, outputs: {:?}",
        operator_input_amount,
        peg_out_tx.vsize(),
        peg_out_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .collect::<Vec<u64>>(),
    );
    println!(
        ">>>>>> PEG OUT TX OUTPUTS SIZE: {:?}",
        peg_out_tx
            .output
            .iter()
            .map(|o| o.size())
            .collect::<Vec<usize>>()
    );
    check_tx_output_sum(INITIAL_AMOUNT, &peg_out_tx);
    // mine peg-out
    let peg_out_result = config.client_0.esplora.broadcast(&peg_out_tx).await;
    println!("Peg Out Tx result: {:?}", peg_out_result);
    assert!(peg_out_result.is_ok());
    println!("Peg Out Txid: {:?}", peg_out_txid);
}
