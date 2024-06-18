use bitcoin::{
  consensus::encode::serialize_hex, Amount, OutPoint, TxOut
};

use bitvm::{
  self, 
  bridge::{ 
    components::{
      bridge::BridgeTransaction, challenge::ChallengeTransaction, connector_a::{generate_address as generate_a_address}, helper::{generate_pay_to_pubkey_script_address_normal, Input},
    }, 
    graph::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT}
  }
};

use super::super::setup::setup_test;


#[tokio::test]
async fn test_challenge_tx() {
    let (client, context) = setup_test();

    let funding_utxo_0 = client
      .get_initial_utxo(
        generate_a_address(&context.operator_pubkey.unwrap(), &context.n_of_n_pubkey.unwrap()),
        Amount::from_sat(DUST_AMOUNT),
      )
      .await
      .unwrap_or_else(|| {
          panic!(
              "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
              generate_a_address(&context.operator_pubkey.unwrap(), &context.n_of_n_pubkey.unwrap()),
              DUST_AMOUNT
          );
      });

    let funding_utxo_crowdfunding = client
      .get_initial_utxo(
        generate_pay_to_pubkey_script_address_normal(&context.depositor_pubkey_normal.unwrap()),
        Amount::from_sat(INITIAL_AMOUNT),
      )
      .await
      .unwrap_or_else(|| {
          panic!(
              "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
              generate_pay_to_pubkey_script_address_normal(&context.depositor_pubkey_normal.unwrap()),
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
    let input_0: Input = (
      funding_outpoint_0,
      input_amount_0,
    );
    let input_crowdfunding: Input = (
      funding_outpoint_crowdfunding,
      input_amount_crowdfunding,
    );

    let prev_tx_out_0 = TxOut {
        value: Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT),
        script_pubkey: generate_a_address(&context.operator_pubkey.unwrap(), &context.n_of_n_pubkey.unwrap())
          .script_pubkey(),
    };

    let mut challenge_tx = ChallengeTransaction::new(
        &context,
        input_0,
        input_amount_crowdfunding,
    );

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
