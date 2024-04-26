use crate::treepp::*;
use bitcoin::{
    absolute,
    key::{Keypair, Secp256k1},
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, Amount, Network, OutPoint, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use lazy_static::lazy_static;
use std::{collections::HashMap, str::FromStr};

pub const INITIAL_AMOUNT: u64 = 100_000;
pub const FEE_AMOUNT: u64 = 1_000;

lazy_static! {
    static ref UNSPENDABLE_PUBKEY: XOnlyPublicKey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    )
    .unwrap();
}

// DEMO SECRETS
// const OPERATOR_SECRET: &str = "d898098e09898a0980989b980809809809f09809884324874302975287524398";
const N_OF_N_SECRET: &str = "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497";

pub type CompiledBitVMGraph = HashMap<OutPoint, Vec<Transaction>>;

pub fn funding_script() -> Script {
    /*
    let secp = Secp256k1::new();
    //let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
    let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
    script! {
        { n_of_n_key.x_only_public_key().0 }
        OP_CHECKSIG
    }*/
    script! {}
}

pub fn funding_taproot_spend_info() -> TaprootSpendInfo {
    let secp = Secp256k1::new();

    let script = funding_script();
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script)
        .expect("Could not add script")
        .finalize(&secp, *UNSPENDABLE_PUBKEY)
        .unwrap();
    taproot_spend_info
}

pub fn funding_address() -> Address {
    Address::p2tr_tweaked(funding_taproot_spend_info().output_key(), Network::Testnet)
}

pub fn funding_spend_tx(funding_outpoint: OutPoint, funding_value: Amount) -> Transaction {
    let secp = Secp256k1::new();
    let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();

    let prevout_script = funding_script();
    let taproot_spend_info = funding_taproot_spend_info();
    let script_ver = (prevout_script.clone(), LeafVersion::TapScript);
    let control_block = taproot_spend_info
        .control_block(&script_ver)
        .expect("Failed to get control_block");

    // Create Transaction
    let input = TxIn {
        previous_output: funding_outpoint,
        script_sig: Script::new(),
        sequence: bitcoin::Sequence(0xFFFFFFFF),
        witness: Witness::default(),
    };

    let output = TxOut {
        value: funding_value - Amount::from_sat(FEE_AMOUNT),
        script_pubkey: funding_address().script_pubkey(),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    // Sign the transaction with n_of_n key
    let mut sighash_cache = SighashCache::new(&mut tx);
    let prev_tx_out = TxOut {
        value: funding_value,
        script_pubkey: funding_address().script_pubkey(),
    };

    let prevouts = vec![prev_tx_out];
    let prevouts = Prevouts::All(&prevouts);
    let sighash_type = TapSighashType::Default;
    let leaf_hash =
        TapLeafHash::from_script(prevout_script.clone().as_script(), LeafVersion::TapScript);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
        .expect("Failed to construct sighash");

    let msg = Message::from(sighash);
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &n_of_n_key);

    let tr_signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };

    // Sanity check
    secp.verify_schnorr(&signature, &msg, &n_of_n_key.x_only_public_key().0)
        .expect("Schnorr verification failed");

    // Fill in the witness
    let witness = Witness::from(vec![
        tr_signature.to_vec(),
        prevout_script.to_bytes(),
        control_block.serialize(),
    ]);
    *sighash_cache.witness_mut(0).unwrap() = witness;
    sighash_cache.into_transaction().clone()
}

pub fn compile_graph(initial_outpoint: OutPoint) -> CompiledBitVMGraph {
    let mut graph = HashMap::new();
    // Simple example Graph that repeats the same transaction 3 times
    // spend_1 -> spend_2 -> spend_3

    let spend_1_tx = funding_spend_tx(initial_outpoint, Amount::from_sat(INITIAL_AMOUNT));
    let spend_1_outpoint = OutPoint {
        txid: spend_1_tx.compute_txid(),
        vout: 0,
    };
    let spend_2_tx = funding_spend_tx(spend_1_outpoint, spend_1_tx.output[0].value);
    let spend_2_outpoint = OutPoint {
        txid: spend_2_tx.compute_txid(),
        vout: 0,
    };
    let spend_3_tx = funding_spend_tx(spend_2_outpoint, spend_2_tx.output[0].value);

    graph.insert(initial_outpoint, vec![spend_1_tx]);
    graph.insert(spend_1_outpoint, vec![spend_2_tx]);
    graph.insert(spend_2_outpoint, vec![spend_3_tx]);
    graph
}

#[cfg(test)]
mod tests {

    use crate::bridge::client::BitVMClient;

    use super::*;

    use bitcoin::consensus::encode::serialize_hex;

    #[tokio::test]
    async fn test_graph_script_spend_funding() {
        let client = BitVMClient::new();
        let funding_utxo = client.get_initial_utxo(funding_address()).await.unwrap();
        let funding_outpoint = OutPoint {
            txid: funding_utxo.txid,
            vout: funding_utxo.vout,
        };
        let tx = funding_spend_tx(funding_outpoint, Amount::from_sat(INITIAL_AMOUNT));
        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_graph_generate_funding_address() {
        println!(
            "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
            funding_address(),
            INITIAL_AMOUNT
        );
        assert!(true);
    }

    #[tokio::test]
    async fn test_get_initial_utxo() {
        let client = BitVMClient::new();
        let utxo = client.get_initial_utxo(funding_address()).await;
        match utxo {
            Some(utxo) => {
                println!("Found {:?}", utxo);
                assert!(true);
            }
            None => {
                println!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    funding_address(),
                    INITIAL_AMOUNT
                );
                assert!(false);
            }
        };
    }

    #[tokio::test]
    async fn test_graph_compile_with_client() {
        let mut client = BitVMClient::new();
        let funding_utxo = client
            .get_initial_utxo(funding_address())
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    funding_address(),
                    INITIAL_AMOUNT
                );
            });
        let funding_outpoint = OutPoint {
            txid: funding_utxo.txid,
            vout: funding_utxo.vout,
        };
        client
            .listen(funding_outpoint, &mut compile_graph(funding_outpoint))
            .await;
        assert!(true);
    }
}
