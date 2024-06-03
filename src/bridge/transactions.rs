#[cfg(test)]
mod tests {

    use bitcoin::{
        key::{Keypair, Secp256k1},
        Amount, OutPoint,
        TxOut
    };

    use crate::bridge::{
        client::BitVMClient,
        graph::{DUST_AMOUNT, INITIAL_AMOUNT, OPERATOR_SECRET, N_OF_N_SECRET, UNSPENDABLE_SECRET},
    };

    use super::*;

    use bitcoin::consensus::encode::serialize_hex;

    #[tokio::test]
    async fn test_disprove_tx() {
        let secp = Secp256k1::new();
        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let unspendable_pubkey = Keypair::from_seckey_str(&secp, UNSPENDABLE_SECRET).unwrap();
        let client = BitVMClient::new();
        let funding_utxo_1 = client
            .get_initial_utxo(
                connector_c_address(n_of_n_key.x_only_public_key().0),
                Amount::from_sat(INITIAL_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    connector_c_address(n_of_n_key.x_only_public_key().0),
                    INITIAL_AMOUNT
                );
            });
        let funding_utxo_0 = client
            .get_initial_utxo(
                connector_c_pre_sign_address(n_of_n_key.x_only_public_key().0),
                Amount::from_sat(DUST_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    connector_c_pre_sign_address(n_of_n_key.x_only_public_key().0),
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
            script_pubkey: connector_c_address(n_of_n_key.x_only_public_key().0).script_pubkey(),
        };
        let prev_tx_out_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c_pre_sign_address(n_of_n_key.x_only_public_key().0)
                .script_pubkey(),
        };
        let mut context = BridgeContext::new();
        context.set_operator_key(operator_key);
        context.set_n_of_n_pubkey(n_of_n_key.x_only_public_key().0);
        context.set_unspendable_pubkey(unspendable_pubkey.x_only_public_key().0);

        let mut disprove_tx = DisproveTransaction::new(
            &context,
            funding_outpoint_1,
            funding_outpoint_0,
            Amount::from_sat(INITIAL_AMOUNT),
            Amount::from_sat(DUST_AMOUNT),
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
