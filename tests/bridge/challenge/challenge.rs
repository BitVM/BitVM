use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint, TxOut};

use bitvm::{
    self,
    bridge::{
        components::{
            bridge::BridgeTransaction,
            challenge::ChallengeTransaction,
            connector::*,
            connector_a::ConnectorA,
            helper::{generate_pay_to_pubkey_script_address, Input},
        },
        graph::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT},
    },
};

use super::super::setup::setup_test;

#[tokio::test]
async fn test_challenge_tx() {
    let (client, context) = setup_test();

    let connector_a = ConnectorA::new(
        context.network,
        &context.operator_taproot_public_key.unwrap(),
        &context.n_of_n_taproot_public_key.unwrap(),
    );

    let funding_utxo_0 = client
        .get_initial_utxo(
            connector_a.generate_taproot_address(),
            Amount::from_sat(DUST_AMOUNT),
        )
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                connector_a.generate_taproot_address(),
                DUST_AMOUNT
            );
        });

    let funding_utxo_crowdfunding = client
        .get_initial_utxo(
            generate_pay_to_pubkey_script_address(
                context.network,
                &context.depositor_public_key.unwrap(),
            ),
            Amount::from_sat(INITIAL_AMOUNT),
        )
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                generate_pay_to_pubkey_script_address(
                    context.network,
                    &context.depositor_public_key.unwrap()
                ),
                INITIAL_AMOUNT
            );
        });

    let funding_outpoint_0 = OutPoint {
        txid: funding_utxo_0.txid,
        vout: funding_utxo_0.vout,
    };
    let funding_outpoint_crowdfunding = OutPoint {
        txid: funding_utxo_crowdfunding.txid,
        vout: funding_utxo_crowdfunding.vout,
    };

    let input_amount_0 = Amount::from_sat(DUST_AMOUNT);
    let input_amount_crowdfunding = Amount::from_sat(INITIAL_AMOUNT);
    let input_0 = Input {
        outpoint: funding_outpoint_0,
        amount: input_amount_0,
    };
    let input_crowdfunding = Input {
        outpoint: funding_outpoint_crowdfunding,
        amount: input_amount_crowdfunding,
    };

    let prev_tx_out_0 = TxOut {
        value: Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT),
        script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
    };

    let mut challenge_tx = ChallengeTransaction::new(&context, input_0, input_amount_crowdfunding);

    challenge_tx.pre_sign(&context);
    challenge_tx.add_input(&context, funding_outpoint_crowdfunding);
    let tx = challenge_tx.finalize(&context);
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
