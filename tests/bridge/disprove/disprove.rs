#[cfg(test)]
mod tests {

    use bitcoin::{
        consensus::encode::serialize_hex, key::Keypair, Amount, Network, PrivateKey, PublicKey,
        TxOut,
    };

    use bitvm::bridge::{
        connectors::connector::TaprootConnector,
        graphs::base::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT},
        scripts::generate_pay_to_pubkey_script,
        transactions::{
            base::{BaseTransaction, Input},
            disprove::DisproveTransaction,
        },
    };

    use super::super::super::{helper::generate_stub_outpoint, setup::setup_test};

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_tx_successfully() {
        let (
            client,
            _,
            _,
            operator_context,
            verifier_0_context,
            verifier_1_context,
            _,
            _,
            _,
            connector_c,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
        ) = setup_test().await;

        let amount_0 = Amount::from_sat(DUST_AMOUNT);
        let outpoint_0 =
            generate_stub_outpoint(&client, &connector_c.generate_taproot_address(), amount_0)
                .await;

        let amount_1 = Amount::from_sat(INITIAL_AMOUNT);
        let outpoint_1 =
            generate_stub_outpoint(&client, &connector_c.generate_taproot_address(), amount_1)
                .await;

        let mut disprove_tx = DisproveTransaction::new(
            &operator_context,
            Input {
                outpoint: outpoint_0,
                amount: amount_0,
            },
            Input {
                outpoint: outpoint_1,
                amount: amount_1,
            },
            1,
        );

        let secret_nonces_0 = disprove_tx.push_nonces(&verifier_0_context);
        let secret_nonces_1 = disprove_tx.push_nonces(&verifier_1_context);

        disprove_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
        disprove_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

        let tx = disprove_tx.finalize();
        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_tx_with_verifier_added_to_output_successfully()
    {
        let (
            client,
            _,
            _,
            operator_context,
            verifier_0_context,
            verifier_1_context,
            _,
            _,
            _,
            connector_c,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
        ) = setup_test().await;

        let amount_0 = Amount::from_sat(DUST_AMOUNT);
        let outpoint_0 =
            generate_stub_outpoint(&client, &connector_c.generate_taproot_address(), amount_0)
                .await;

        let amount_1 = Amount::from_sat(INITIAL_AMOUNT);
        let outpoint_1 =
            generate_stub_outpoint(&client, &connector_c.generate_taproot_address(), amount_1)
                .await;

        let mut disprove_tx = DisproveTransaction::new(
            &operator_context,
            Input {
                outpoint: outpoint_0,
                amount: amount_0,
            },
            Input {
                outpoint: outpoint_1,
                amount: amount_1,
            },
            1,
        );

        let secret_nonces_0 = disprove_tx.push_nonces(&verifier_0_context);
        let secret_nonces_1 = disprove_tx.push_nonces(&verifier_1_context);

        disprove_tx.pre_sign(&verifier_0_context, &secret_nonces_0);
        disprove_tx.pre_sign(&verifier_1_context, &secret_nonces_1);

        let mut tx = disprove_tx.finalize();

        let secp = verifier_0_context.secp;
        let verifier_secret: &str =
            "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
        let verifier_keypair = Keypair::from_seckey_str(&secp, verifier_secret).unwrap();
        let verifier_private_key = PrivateKey::new(verifier_keypair.secret_key(), Network::Testnet);
        let verifier_pubkey = PublicKey::from_private_key(&secp, &verifier_private_key);

        let verifier_output = TxOut {
            value: (Amount::from_sat(INITIAL_AMOUNT) - Amount::from_sat(FEE_AMOUNT)) / 2,
            script_pubkey: generate_pay_to_pubkey_script(&verifier_pubkey),
        };

        tx.output.push(verifier_output);

        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }
}
