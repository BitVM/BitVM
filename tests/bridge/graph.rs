use bitcoin::{Amount, OutPoint};
use bitvm::bridge::{components::connector::TaprootConnector, graph::{compile_graph, INITIAL_AMOUNT}};

use crate::bridge::setup::setup_test;

#[tokio::test]
    async fn test_graph_compile_with_client() {
        let (mut client, mut context, _, _, connector_c, _, _, _) = setup_test();

        let funding_utxo = client
            .get_initial_utxo(
                connector_c.generate_taproot_address(),
                Amount::from_sat(INITIAL_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    connector_c.generate_taproot_address(),
                    INITIAL_AMOUNT
                );
            });
        let funding_outpoint = OutPoint {
            txid: funding_utxo.txid,
            vout: funding_utxo.vout,
        };
        let mut graph = compile_graph(&context, funding_outpoint);
        client
            .listen(&mut context, funding_outpoint, &mut graph)
            .await;
        assert!(true);
    }