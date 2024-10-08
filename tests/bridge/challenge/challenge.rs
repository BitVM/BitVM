use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint};

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{DUST_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, InputWithScript},
        challenge::ChallengeTransaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_challenge_tx() {
    let (
        client,
        _,
        depositor_context,
        operator_context,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        connector_1,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = setup_test().await;

    // We re-use the depositor private key to imitate a third-party
    let crowdfunding_keypair = &depositor_context.depositor_keypair;
    let crowdfunding_public_key = &depositor_context.depositor_public_key;

    let amount_0 = Amount::from_sat(DUST_AMOUNT);
    let outpoint_0 =
        generate_stub_outpoint(&client, &connector_1.generate_taproot_address(), amount_0).await;

    // Create two inputs that exceed the crowdfunding total
    let input_amount_crowdfunding_total = Amount::from_sat(INITIAL_AMOUNT);

    let address =
        generate_pay_to_pubkey_script_address(depositor_context.network, crowdfunding_public_key);
    let amount_1 = Amount::from_sat(INITIAL_AMOUNT * 2 / 3);

    // Check there are two utxos
    let crowdfunding_utxos = client
        .get_initial_utxos(address.clone(), amount_1)
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                address,
                amount_1.to_sat()
            );
        });

    if crowdfunding_utxos.len() < 2 {
        panic!(
            "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
            address,
            amount_1.to_sat()
        );
    }

    let refund_address =
        generate_pay_to_pubkey_script_address(depositor_context.network, crowdfunding_public_key);

    let mut challenge_tx = ChallengeTransaction::new(
        &operator_context,
        Input {
            outpoint: outpoint_0,
            amount: amount_0,
        },
        input_amount_crowdfunding_total,
    );

    challenge_tx.add_inputs_and_output(
        &depositor_context,
        &vec![
            InputWithScript {
                outpoint: OutPoint {
                    txid: crowdfunding_utxos[0].txid,
                    vout: crowdfunding_utxos[0].vout,
                },
                amount: amount_1,
                script: &generate_pay_to_pubkey_script(crowdfunding_public_key),
            },
            InputWithScript {
                outpoint: OutPoint {
                    txid: crowdfunding_utxos[1].txid,
                    vout: crowdfunding_utxos[1].vout,
                },
                amount: amount_1,
                script: &generate_pay_to_pubkey_script(crowdfunding_public_key),
            },
        ],
        crowdfunding_keypair,
        refund_address.script_pubkey(),
    );

    let tx = challenge_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());

    // assert refund balance
    let challenge_txid = tx.compute_txid();
    let refund_utxos = client
        .esplora
        .get_address_utxo(refund_address)
        .await
        .unwrap();
    let refund_utxo = refund_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == challenge_txid);
    assert!(refund_utxo.is_some());
    assert_eq!(
        refund_utxo.unwrap().value,
        amount_1 * 2 - input_amount_crowdfunding_total
    );
}
