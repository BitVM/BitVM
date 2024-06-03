use bitcoin::{
    OutPoint, XOnlyPublicKey,
};
use lazy_static::lazy_static;
use std::{collections::HashMap, str::FromStr};

use super::context::BridgeContext;
use super::components::bridge::BridgeTransaction;

pub const INITIAL_AMOUNT: u64 = 100_000;
pub const FEE_AMOUNT: u64 = 1_000;
pub const DUST_AMOUNT: u64 = 10_000;

lazy_static! {
    static ref UNSPENDABLE_PUBKEY: XOnlyPublicKey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    )
    .unwrap();
}

// DEMO SECRETS
pub const OPERATOR_SECRET: &str =
    "d898098e09898a0980989b980809809809f09809884324874302975287524398";
pub const N_OF_N_SECRET: &str = "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497";
pub const UNSPENDABLE_SECRET: &str = "8ylb10hs645nwc04f47cnnlggvh0np1yi9kp2fk40k3aq96k1kc1n1h09n0ag68e"; // TODO: don't use known secret for unspendable key

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

    use crate::bridge::{client::BitVMClient, transactions::connector_c_address};

    use super::*;
    use bitcoin::{Amount, secp256k1::{Secp256k1, Keypair}};

    #[tokio::test]
    async fn test_graph_compile_with_client() {
        let secp = Secp256k1::new();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let unspendable_pubkey = Keypair::from_seckey_str(&secp, UNSPENDABLE_SECRET).unwrap();
        let mut context = BridgeContext::new();
        context.set_operator_key(operator_key);
        context.set_n_of_n_pubkey(n_of_n_key.x_only_public_key().0);
        context.set_unspendable_pubkey(unspendable_pubkey.x_only_public_key().0);

        let mut client = BitVMClient::new();
        let funding_utxo = client
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
