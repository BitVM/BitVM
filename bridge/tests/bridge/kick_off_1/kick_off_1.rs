use bitcoin::Amount;

use bridge::{
    commitments::CommitmentMessageId,
    connectors::base::TaprootConnector,
    graphs::base::DUST_AMOUNT,
    transactions::{
        base::{BaseTransaction, Input, MIN_RELAY_FEE_KICK_OFF_1, MIN_RELAY_FEE_START_TIME},
        kick_off_1::KickOff1Transaction,
    },
};

use bitvm::signatures::signing_winternitz::WinternitzSigningInputs;

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{check_tx_output_sum, generate_stub_outpoint},
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_kick_off_1_tx_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let subsequent_tx_fee = MIN_RELAY_FEE_START_TIME + DUST_AMOUNT * 2;
    let input_amount =
        Amount::from_sat(INITIAL_AMOUNT + MIN_RELAY_FEE_KICK_OFF_1 + subsequent_tx_fee);
    let funding_address = config.connector_6.generate_taproot_address();
    faucet
        .fund_input(&funding_address, input_amount)
        .await
        .wait()
        .await;
    let funding_outpoint_0 =
        generate_stub_outpoint(&config.client_0, &funding_address, input_amount).await;

    let input = Input {
        outpoint: funding_outpoint_0,
        amount: input_amount,
    };

    let mut kick_off_1_tx = KickOff1Transaction::new(
        &config.operator_context,
        &config.connector_1,
        &config.connector_2,
        &config.connector_6,
        input,
    );
    let ethereum_txid = "8b274fbb76c72f66c467c976c61d5ac212620e036818b5986a33f7b557cb2de8";
    let bitcoin_txid = "8b4cce4a1a9522392c095df6416533d89e1e6ac7bdf8ab3c1685426b321ed182";
    let source_network_txid_digits = WinternitzSigningInputs {
        message: bitcoin_txid.as_bytes(),
        signing_key: &config.commitment_secrets[&CommitmentMessageId::PegOutTxIdSourceNetwork],
    };
    let destination_network_txid_digits = WinternitzSigningInputs {
        message: ethereum_txid.as_bytes(),
        signing_key: &config.commitment_secrets[&CommitmentMessageId::PegOutTxIdDestinationNetwork],
    };
    kick_off_1_tx.sign(
        &config.operator_context,
        &config.connector_6,
        &source_network_txid_digits,
        &destination_network_txid_digits,
    );

    let tx = kick_off_1_tx.finalize();
    check_tx_output_sum(INITIAL_AMOUNT + subsequent_tx_fee, &tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Kick Off 1 tx result: {:?}\n", result);
    assert!(result.is_ok());
}
