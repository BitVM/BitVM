#![allow(dead_code)]
use crate::treepp::*;
use bitcoin::{
    absolute,
    key::{Keypair, Secp256k1},
    secp256k1::Message,
    sighash::{Prevouts, ScriptPath, SighashCache},
    taproot::{LeafVersion, TapLeaf, TaprootBuilder, TaprootSpendInfo},
    Address, Amount, Network, TapLeafHash, TapSighashType, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use esplora_client::{
    api::transaction::OutPoint, AsyncClient, BlockHash, Builder, Transaction, Txid, Utxo,
};
use serde::Serialize;
use std::{
    borrow::BorrowMut, collections::HashMap, hash::Hash, str::FromStr, thread::sleep,
    time::Duration,
};

const ESPLORA_URL: &str = "https://mutinynet.com/api";
const INITIAL_AMOUNT: u64 = 100_000;
const FEE_AMOUNT: u64 = 10_000;

const UNSPENDABLE_PUBKEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

// DEMO KEYS
const OPERATOR_SECRET: &str = "d898098e09898a0980989b980809809809f09809884324874302975287524398";
const N_OF_N_SECRET: &str = "a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497";

pub type CompiledBitVMGraph = HashMap<OutPoint, Vec<Transaction>>;

pub struct BitVMClient {
    // Maps OutPoints to their (potentially unconfirmed) UTXOs.
    pub utxo_set: HashMap<OutPoint, Utxo>,
    pub esplora: AsyncClient,
}

pub fn funding_script() -> Script {
    let secp = Secp256k1::new();
    //let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
    let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
    script! {
        { n_of_n_key.x_only_public_key().0 }
        OP_CHECKSIG
    }
}

pub fn funding_taproot_spend_info() -> TaprootSpendInfo {
    let secp = Secp256k1::new();
    let unspendable_taproot_key = Keypair::from_seckey_str(&secp, UNSPENDABLE_PUBKEY).unwrap();

    let script = funding_script();
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script)
        .expect("Could not add script")
        .finalize(&secp, unspendable_taproot_key.x_only_public_key().0)
        .unwrap();
    taproot_spend_info
}

pub fn funding_address() -> Address {
    Address::p2tr_tweaked(funding_taproot_spend_info().output_key(), Network::Testnet)
}

pub fn funding_spend_tx(funding_outpoint: OutPoint) -> Transaction {
    let secp = Secp256k1::new();
    let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();

    let prevout_script = funding_script();
    let taproot_spend_info = funding_taproot_spend_info();
    let script_ver = (prevout_script.clone(), LeafVersion::TapScript);
    let control_block = taproot_spend_info
        .control_block(&script_ver)
        .expect("Failed to get control_block");

    let input = TxIn {
        previous_output: funding_outpoint,
        script_sig: Script::new(),
        sequence: bitcoin::Sequence(0xFFFFFFFF),
        witness: Witness::default(),
    };

    let output = TxOut {
        value: bitcoin::Amount::from_sat(INITIAL_AMOUNT - FEE_AMOUNT),
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
        value: bitcoin::Amount::from_sat(INITIAL_AMOUNT),
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

    // Fill in the spend_input witness
    let tr_signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };

    // Sanity check that the signature is correct
    secp.verify_schnorr(&signature, &msg, &n_of_n_key.x_only_public_key().0)
        .expect("Schnorr verification failed");
    let mut witness = Witness::new();
    witness.push(tr_signature.serialize());
    witness.push(prevout_script.to_bytes());
    witness.push(control_block.serialize());
    *sighash_cache.witness_mut(0).unwrap() = witness;
    sighash_cache.into_transaction().clone()
}

pub fn compile_graph(initial_outpoint: OutPoint) -> CompiledBitVMGraph {
    //let graph = HashMap::new();
    //let secp = Secp256k1::new();
    //let musig_key = Keypair::from_seckey_str(&secp, "TEST").unwrap();
    //let unspendable_taproot_key = Keypair::from_seckey_str(&secp, UNSPENDABLE_PUBKEY).unwrap();

    //graph.insert(initial_outpoint, vec![n_of_n_spend_tx]);
    //graph
    todo!()
}

impl BitVMClient {
    pub fn new() -> Self {
        Self {
            utxo_set: HashMap::new(),
            esplora: Builder::new(ESPLORA_URL)
                .build_async()
                .expect("Could not build esplora client"),
        }
    }

    pub async fn get_initial_utxo(&self, address: Address) -> Option<Utxo> {
        let utxos = self.esplora.get_address_utxo(address).await.unwrap();
        let possible_utxos = utxos
            .into_iter()
            .filter(|utxo| utxo.value == bitcoin::Amount::from_sat(INITIAL_AMOUNT))
            .collect::<Vec<_>>();
        if possible_utxos.len() > 0 {
            Some(possible_utxos[0].clone())
        } else {
            None
        }
    }

    pub async fn listen(&mut self, initial_utxo: Utxo, graph: &CompiledBitVMGraph) {
        let builder = Builder::new(ESPLORA_URL);
        let esplora = builder.build_async().unwrap();
        let mut latest_hash =
            BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let utxo_set = &mut self.utxo_set;

        loop {
            match esplora.get_tip_hash().await {
                Ok(block_hash) => {
                    if block_hash == latest_hash {
                        sleep(Duration::from_secs(10));
                        continue;
                    }
                    latest_hash = block_hash;
                    // TODO: This assumes that the tip did not increase. There should be a
                    // better API endpoint like /block-height/{block_hash}
                    let block_height = esplora.get_height().await.unwrap();
                    let block = esplora
                        .get_block_by_hash(&block_hash)
                        .await
                        .unwrap()
                        .unwrap();

                    // Handle new block received logic
                    println!("Received block {}", block_hash);

                    for tx in block.txdata {
                        // TODO: Check if this transaction belongs to our graph

                        // Update our UTXO set
                        //update_utxo_set(utxo_set, tx, block_height);
                    }

                    // Iterate through our UTXO set and execute an executable TX
                    // TODO: May have to respect an order here.
                    for utxo in utxo_set.values() {
                        let outpoint = OutPoint {
                            txid: utxo.txid,
                            vout: utxo.vout,
                        };

                        match graph.get(&outpoint) {
                            Some(children) => {
                                for tx in children {
                                    println!("{:?}", tx);
                                    // try execute the TX
                                    // TODO: iterate through the TX's leaves and try to execute them
                                }
                            }
                            None => continue,
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }
}

fn update_utxo_set(utxo_set: &mut HashMap<(Txid, u32), u32>, tx: Transaction, block_height: u32) {
    println!("Utxo set: {:?}", utxo_set);
    // Update our UTXO set
    for input in &tx.input {
        utxo_set.remove(&(input.previous_output.txid, input.previous_output.vout));
    }
    // Register all vouts of the transaction
    for (i, vout) in tx.output.iter().enumerate() {
        // TODO: Check if the vout is used by the current Player in the graph
        let txid = tx.txid();
        utxo_set.insert((txid, i as u32), block_height);
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use serde_json;

    use bitcoin::{consensus::encode::serialize_hex, key::Secp256k1, taproot::TaprootBuilder};

    #[tokio::test]
    async fn test_graph_script_spend_funding() {
        let client = BitVMClient::new();
        let funding_utxo = client.get_initial_utxo(funding_address()).await.unwrap();
        let funding_outpoint = OutPoint {
            txid: funding_utxo.txid,
            vout: funding_utxo.vout,
        };
        let tx = funding_spend_tx(funding_outpoint);
        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(false);
    }

    #[tokio::test]
    async fn test_graph_generate_funding_address() {
        println!("Fund {:?} with {} sats at https://faucet.mutinynet.com/", funding_address(), INITIAL_AMOUNT);
        assert!(false);
    }

    #[tokio::test]
    async fn test_get_initial_utxo() {
        let client = BitVMClient::new();
        let utxo = client
            .get_initial_utxo(
                Address::from_str("tb1p4e8pqfj998xf72ypkkvmya3kvhlqq0u90kt36qy47yzyv2vx0e5spld8hx")
                    .unwrap()
                    .require_network(bitcoin::Network::Testnet)
                    .unwrap(),
            )
            .await;
        match utxo {
            Some(utxo) => {
                println!("Found {:?}", utxo);
                assert!(true);
            }
            None => {
                println!(
                    "Address not funded. Fund at https://faucet.mutinynet.com/ with {}",
                    INITIAL_AMOUNT
                );
                assert!(false);
            }
        };
    }
}
