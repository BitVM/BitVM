use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_confirm::PegInConfirmTransaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_in_confirm_tx() {
    let (
        client,
        _,
        depositor_context,
        _,
        verifier_0_context,
        verifier_1_context,
        _,
        _,
        _,
        _,
        connector_z,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        depositor_evm_address,
        _,
    ) = setup_test().await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let outpoint =
        generate_stub_outpoint(&client, &connector_z.generate_taproot_address(), amount).await;

    let mut peg_in_confirm_tx = PegInConfirmTransaction::new(
        &depositor_context,
        &depositor_evm_address,
        Input { outpoint, amount },
    );

    let secret_nonces_0 = peg_in_confirm_tx.push_nonces(&verifier_0_context);
    let secret_nonces_1 = peg_in_confirm_tx.push_nonces(&verifier_1_context);

    peg_in_confirm_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
    peg_in_confirm_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

    let tx = peg_in_confirm_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
