use bitcoin::{consensus::encode::serialize_hex, Amount, OutPoint};

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graph::{DUST_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, InputWithScript},
        challenge::ChallengeTransaction,
    },
};

use super::super::setup::setup_test;

#[tokio::test]
async fn test_challenge_tx() {
    let (client, depositor_context, operator_context, _, _, connector_a, _, _, _, _, _, _, _) =
        setup_test();

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

    let crowdfunding_utxo_amount_raw = INITIAL_AMOUNT * 2 / 3;
    let crowdfunding_utxo_amount = Amount::from_sat(crowdfunding_utxo_amount_raw);
    let crowdfunding_utxos = client
        .get_initial_utxos(
            generate_pay_to_pubkey_script_address(
                depositor_context.network,
                crowdfunding_public_key,
            ),
            crowdfunding_utxo_amount,
        )
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                generate_pay_to_pubkey_script_address(
                    depositor_context.network,
                    crowdfunding_public_key
                ),
                crowdfunding_utxo_amount
            );
        });

    if crowdfunding_utxos.len() < 2 {
        panic!(
            "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
            generate_pay_to_pubkey_script_address(
                depositor_context.network,
                crowdfunding_public_key
            ),
            crowdfunding_utxo_amount_raw
        );
    }

    let input_amount_0 = Amount::from_sat(DUST_AMOUNT);
    let input_amount_crowdfunding_total = Amount::from_sat(INITIAL_AMOUNT);

    let funding_outpoint_0 = OutPoint {
        txid: funding_utxo_0.txid,
        vout: funding_utxo_0.vout,
    };

    let funding_input_with_script_0 = InputWithScript {
        outpoint: OutPoint {
            txid: crowdfunding_utxos[0].txid,
            vout: crowdfunding_utxos[0].vout,
        },
        amount: crowdfunding_utxo_amount,
        script: &generate_pay_to_pubkey_script(crowdfunding_public_key),
    };
    let funding_input_with_script_1 = InputWithScript {
        outpoint: OutPoint {
            txid: crowdfunding_utxos[1].txid,
            vout: crowdfunding_utxos[1].vout,
        },
        amount: crowdfunding_utxo_amount,
        script: &generate_pay_to_pubkey_script(crowdfunding_public_key),
    };

    let input_0 = Input {
        outpoint: funding_outpoint_0,
        amount: input_amount_0,
    };

    let refund_address =
        generate_pay_to_pubkey_script_address(depositor_context.network, crowdfunding_public_key);

    let mut challenge_tx =
        ChallengeTransaction::new(&operator_context, input_0, input_amount_crowdfunding_total);

    challenge_tx.add_inputs_and_output(
        &depositor_context,
        &vec![funding_input_with_script_0, funding_input_with_script_1],
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
    let challenge_tx_id = tx.compute_txid();
    let refund_utxos = client
        .esplora
        .get_address_utxo(refund_address)
        .await
        .unwrap();
    let refund_utxo = refund_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == challenge_tx_id);
    assert!(refund_utxo.is_some());
    assert_eq!(
        refund_utxo.unwrap().value,
        crowdfunding_utxo_amount * 2 - input_amount_crowdfunding_total
    );
}
