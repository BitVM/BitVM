use bitcoin::{
    consensus::encode::serialize_hex,
    key::{Keypair, Secp256k1},
    Amount, OutPoint, TxOut,
};

use bitvm::bridge::{
    connectors::connector::P2wshConnector,
    graph::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script,
    transactions::{
        base::{BaseTransaction, Input},
        challenge::ChallengeTransaction,
    },
};

use super::super::setup::setup_test;

#[tokio::test]
async fn test_kick_off_tx() {
    // let secp = Secp256k1::new();

    // let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
    // let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
    // let n_of_n_pubkey = n_of_n_key.x_only_public_key().0;
    // let depositor_key = Keypair::from_seckey_str(&secp, DEPOSITOR_SECRET).unwrap();
    // let depositor_pubkey = depositor_key.x_only_public_key().0;
    // let evm_address = String::from("evm address");

    // let client = BitVMClient::new();
    // let funding_utxo = client.get_initial_utxo(
    //   generate_pay_to_pubkey_script_address(&operator_key.x_only_public_key().0),
    //   Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT)
    // )
    // .await.unwrap_or_else(|| {
    //   panic!(
    //     "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
    //     generate_address(
    //       &evm_address,
    //       &n_of_n_pubkey,
    //       &depositor_pubkey,
    //     ),
    //     INITIAL_AMOUNT + FEE_AMOUNT
    //   );
    // });

    // let funding_utxo_0 = client
    //     .get_initial_utxo(
    //         generate_address(
    //           &evm_address,
    //           &n_of_n_pubkey,
    //           &depositor_pubkey,
    //         ),
    //         Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT),
    //     )
    //     .await
    //     .unwrap_or_else(|| {
    //         panic!(
    //             "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
    //             generate_address(
    //               &evm_address,
    //               &n_of_n_pubkey,
    //               &depositor_pubkey,
    //             ),
    //             INITIAL_AMOUNT + FEE_AMOUNT
    //         );
    //     });
    // let funding_outpoint_0 = OutPoint {
    //     txid: funding_utxo_0.txid,
    //     vout: funding_utxo_0.vout,
    // };

    // let input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    // let input: Input = (
    //   funding_outpoint_0,
    //   input_amount,
    // );

    // let prev_tx_out_0 = TxOut {
    //     value: Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT),
    //     script_pubkey: generate_address(
    //       &evm_address,
    //       &n_of_n_pubkey,
    //       &depositor_pubkey,
    //     ).script_pubkey(),
    // };
    // let mut context = BridgeContext::new();
    // context.set_operator_key(operator_key);
    // context.set_n_of_n_pubkey(n_of_n_pubkey);
    // context.set_depositor_pubkey(depositor_pubkey);
    // context.set_unspendable_pubkey(*UNSPENDABLE_PUBKEY);

    // let mut peg_in_refund_tx = PegInRefundTransaction::new(
    //     &context,
    //     input,
    //     evm_address,
    // );

    // peg_in_refund_tx.pre_sign(&context);
    // let tx = peg_in_refund_tx.finalize(&context);
    // println!("Script Path Spend Transaction: {:?}\n", tx);
    // let result = client.esplora.broadcast(&tx).await;
    // println!("Txid: {:?}", tx.compute_txid());
    // println!("Broadcast result: {:?}\n", result);
    // println!("Transaction hex: \n{}", serialize_hex(&tx));
    // assert!(result.is_ok());
}
