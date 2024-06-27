use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint};

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graph::{DUST_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input},
        challenge::ChallengeTransaction,
    },
};

use super::super::setup::setup_test;

#[tokio::test]
async fn test_challenge_tx() {
    let (
        client,
        depositor_context,
        operator_context,
        verifier_context,
        withdrawer_context,
        connector_a,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test();

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

    // We re-use the depositor private key to imitate a third-party
    let crowdfunding_keypair = &depositor_context.depositor_keypair;
    let crowdfunding_public_key = &depositor_context.depositor_public_key;

    let funding_utxo_crowdfunding = client
        .get_initial_utxo(
            generate_pay_to_pubkey_script_address(
                depositor_context.network,
                crowdfunding_public_key,
            ),
            Amount::from_sat(INITIAL_AMOUNT),
        )
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                generate_pay_to_pubkey_script_address(
                    depositor_context.network,
                    crowdfunding_public_key
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

    let mut challenge_tx =
        ChallengeTransaction::new(&operator_context, input_0, input_amount_crowdfunding);

    challenge_tx.add_input(
        &depositor_context,
        funding_outpoint_crowdfunding,
        &generate_pay_to_pubkey_script(crowdfunding_public_key),
        crowdfunding_keypair,
    );
    let tx = challenge_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
