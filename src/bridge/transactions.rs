#[cfg(test)]
mod tests {

    use bitcoin::{
        Amount, OutPoint, TxOut,
    };

    use crate::bridge::{
        client::BitVMClient,
        components::{
            bridge::BridgeTransaction,
            connector_c::{generate_taproot_address, generate_taproot_pre_sign_address},
            disprove::DisproveTransaction,
        },
        context::BridgeContext,
        graph::{
            DEPOSITOR_SECRET, DUST_AMOUNT, INITIAL_AMOUNT, N_OF_N_SECRET, OPERATOR_SECRET, WITHDRAWER_SECRET, EVM_ADDRESS
        },
    };

    use bitcoin::consensus::encode::serialize_hex;

    #[tokio::test]
    async fn test_disprove_tx() {
        let mut context = BridgeContext::new();
        context.initialize_evm_address(EVM_ADDRESS);
        context.initialize_operator(OPERATOR_SECRET);
        context.initialize_n_of_n(N_OF_N_SECRET);
        context.initialize_depositor(DEPOSITOR_SECRET);
        context.initialize_withdrawer(WITHDRAWER_SECRET);

        let client = BitVMClient::new();
        let funding_utxo_1 = client
            .get_initial_utxo(
                generate_taproot_address(&context.n_of_n_taproot_public_key.unwrap()),
                Amount::from_sat(INITIAL_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    generate_taproot_address(&context.n_of_n_taproot_public_key.unwrap()),
                    INITIAL_AMOUNT
                );
            });
        let funding_utxo_0 = client
            .get_initial_utxo(
                generate_taproot_pre_sign_address(&context.n_of_n_taproot_public_key.unwrap()),
                Amount::from_sat(DUST_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    generate_taproot_pre_sign_address(&context.n_of_n_taproot_public_key.unwrap()),
                    DUST_AMOUNT
                );
            });
        let funding_outpoint_0 = OutPoint {
            txid: funding_utxo_0.txid,
            vout: funding_utxo_0.vout,
        };
        let funding_outpoint_1 = OutPoint {
            txid: funding_utxo_1.txid,
            vout: funding_utxo_1.vout,
        };
        let prev_tx_out_1 = TxOut {
            value: Amount::from_sat(INITIAL_AMOUNT),
            script_pubkey: generate_taproot_address(&context.n_of_n_taproot_public_key.unwrap()).script_pubkey(),
        };
        let prev_tx_out_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: generate_taproot_pre_sign_address(&context.n_of_n_taproot_public_key.unwrap()).script_pubkey(),
        };

        let mut disprove_tx = DisproveTransaction::new(
            &context,
            (funding_outpoint_0, Amount::from_sat(DUST_AMOUNT)),
            (funding_outpoint_1, Amount::from_sat(INITIAL_AMOUNT)),
            1,
        );

        disprove_tx.pre_sign(&context);
        let tx = disprove_tx.finalize(&context);
        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }
}
