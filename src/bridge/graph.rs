use bitcoin::OutPoint;
use std::collections::HashMap;

use super::components::bridge::BridgeTransaction;
use super::context::BridgeContext;

pub const INITIAL_AMOUNT: u64 = 100_000;
pub const FEE_AMOUNT: u64 = 1_000;
pub const DUST_AMOUNT: u64 = 10_000;
pub const ONE_HUNDRED: u64 = 100_000_000;

// TODO delete
// DEMO SECRETS
pub const OPERATOR_SECRET: &str =
    "d898098e09898a0980989b980809809809f09809884324874302975287524398";
pub const N_OF_N_SECRET: &str = "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497";
pub const DEPOSITOR_SECRET: &str =
    "b8f17ea979be24199e7c3fec71ee88914d92fd4ca508443f765d56ce024ef1d7";
pub const WITHDRAWER_SECRET: &str =
    "fffd54f6d8f8ad470cb507fd4b6e9b3ea26b4221a4900cc5ad5916ce67c02f1e";

pub const EVM_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

pub type CompiledBitVMGraph = HashMap<OutPoint, Vec<Box<dyn BridgeTransaction + 'static>>>;

pub fn compile_graph(context: &BridgeContext, initial_outpoint: OutPoint) -> CompiledBitVMGraph {
    // Currently only Assert -> Disprove

    //let mut disprove_txs = vec![];
    //for i in 0..1000 {
    //    let disprove_tx = Box::new(DisproveTransaction::new(
    //        context,
    //        initial_outpoint,
    //        Amount::from_sat(INITIAL_AMOUNT),
    //        i,
    //    ));
    //    disprove_txs.push(disprove_tx as Box<dyn BridgeTransaction + 'static>);
    //}
    //graph.insert(initial_outpoint, disprove_txs);

    // Pre-sign transactions in the graph.
    //for transaction_vec in graph.values_mut() {
    //    for bridge_transaction in transaction_vec.iter_mut() {
    //        bridge_transaction.pre_sign(context);
    //    }
    //}
    HashMap::new()
}

#[cfg(test)]
mod tests {

    use crate::bridge::{client::BitVMClient, components::connector_c::ConnectorC};

    use super::*;
    use bitcoin::{ Amount, Network };

    #[tokio::test]
    async fn test_graph_compile_with_client() {
        let mut context = BridgeContext::new(Network::Testnet);
        context.initialize_evm_address(EVM_ADDRESS);
        context.initialize_operator(OPERATOR_SECRET);
        context.initialize_n_of_n(N_OF_N_SECRET);
        context.initialize_depositor(DEPOSITOR_SECRET);
        context.initialize_withdrawer(WITHDRAWER_SECRET);

        let connector_c = ConnectorC::new(context.network, &context.n_of_n_taproot_public_key.unwrap());

        let mut client = BitVMClient::new();
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
}
