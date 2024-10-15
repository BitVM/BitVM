#[cfg(test)]
mod tests {

    use bitcoin::{
        consensus::encode::serialize_hex, key::Keypair, Amount, PrivateKey, PublicKey, TxOut,
    };

    use bitvm::bridge::{
        connectors::base::TaprootConnector,
        graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
        scripts::generate_pay_to_pubkey_script,
        transactions::{
            base::{BaseTransaction, Input},
            disprove_chain::DisproveChainTransaction,
        },
    };

    use super::super::super::{helper::generate_stub_outpoint, setup::setup_test};

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_chain_tx_successfully() {
        let config = setup_test().await;

        let amount = Amount::from_sat(INITIAL_AMOUNT);
        let outpoint = generate_stub_outpoint(
            &config.client_0,
            &config.connector_b.generate_taproot_address(),
            amount,
        )
        .await;

        let mut disprove_chain_tx =
            DisproveChainTransaction::new(&config.operator_context, Input { outpoint, amount });

        let secret_nonces_0 = disprove_chain_tx.push_nonces(&config.verifier_0_context);
        let secret_nonces_1 = disprove_chain_tx.push_nonces(&config.verifier_1_context);

        disprove_chain_tx.pre_sign(&config.verifier_0_context, &secret_nonces_0);
        disprove_chain_tx.pre_sign(&config.verifier_1_context, &secret_nonces_1);

        let tx = disprove_chain_tx.finalize();
        println!("Script Path Spend Transaction: {:?}\n", tx);

        let result = config.client_0.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_chain_tx_with_verifier_added_to_output_successfully(
    ) {
        let config = setup_test().await;

        let amount = Amount::from_sat(INITIAL_AMOUNT);
        let outpoint = generate_stub_outpoint(
            &config.client_0,
            &config.connector_b.generate_taproot_address(),
            amount,
        )
        .await;

        let mut disprove_chain_tx =
            DisproveChainTransaction::new(&config.operator_context, Input { outpoint, amount });

        let secret_nonces_0 = disprove_chain_tx.push_nonces(&config.verifier_0_context);
        let secret_nonces_1 = disprove_chain_tx.push_nonces(&config.verifier_1_context);

        disprove_chain_tx.pre_sign(&config.verifier_0_context, &secret_nonces_0);
        disprove_chain_tx.pre_sign(&config.verifier_1_context, &secret_nonces_1);

        let mut tx = disprove_chain_tx.finalize();

        let secp = config.verifier_0_context.secp;
        let verifier_secret: &str =
            "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
        let verifier_keypair = Keypair::from_seckey_str(&secp, verifier_secret).unwrap();
        let verifier_private_key = PrivateKey::new(
            verifier_keypair.secret_key(),
            config.verifier_0_context.network,
        );
        let verifier_pubkey = PublicKey::from_private_key(&secp, &verifier_private_key);

        let verifier_output = TxOut {
            value: (Amount::from_sat(INITIAL_AMOUNT) - Amount::from_sat(FEE_AMOUNT)) * 5 / 100,
            script_pubkey: generate_pay_to_pubkey_script(&verifier_pubkey),
        };

        tx.output.push(verifier_output);

        println!("Script Path Spend Transaction: {:?}\n", tx);

        let result = config.client_0.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }
}
