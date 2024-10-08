use bitcoin::{consensus::encode::serialize_hex, Amount};

use bitvm::bridge::{
    connectors::connector::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    transactions::{
        base::{BaseTransaction, Input},
        peg_in_refund::PegInRefundTransaction,
    },
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_in_refund_tx() {
    let (
        client,
        _,
        depositor_context,
        _,
        _,
        _,
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

    let peg_in_refund_tx = PegInRefundTransaction::new(
        &depositor_context,
        &depositor_evm_address,
        Input { outpoint, amount },
    );

    let tx = peg_in_refund_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = client.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
