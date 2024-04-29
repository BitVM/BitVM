use std::{collections::HashMap, thread::sleep, time::Duration};

use crate::bridge::graph::INITIAL_AMOUNT;
use bitcoin::{absolute::Height, Address, OutPoint};
use esplora_client::{AsyncClient, BlockHash, Builder, Utxo};
use std::str::FromStr;

use super::graph::CompiledBitVMGraph;

const ESPLORA_URL: &str = "https://mutinynet.com/api";

pub type UtxoSet = HashMap<OutPoint, Height>;

pub struct BitVMClient {
    // Maps OutPoints to their (potentially unconfirmed) UTXOs.
    pub utxo_set: UtxoSet,
    pub esplora: AsyncClient,
}

impl BitVMClient {
    pub fn new() -> Self {
        Self {
            utxo_set: UtxoSet::new(),
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

    pub async fn listen(&mut self, initial_outpoint: OutPoint, graph: &mut CompiledBitVMGraph) {
        let builder = Builder::new(ESPLORA_URL);
        let esplora = builder.build_async().unwrap();
        let mut latest_hash =
            BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        self.utxo_set.insert(initial_outpoint, Height::ZERO);

        while !graph.is_empty() {
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
                        for (vout, _) in tx.output.iter().enumerate() {
                            let outpoint = OutPoint {
                                txid: tx.compute_txid(),
                                vout: vout as u32,
                            };
                            if graph.contains_key(&outpoint) {
                                // Update our UTXO set
                                self.utxo_set.insert(
                                    outpoint,
                                    Height::from_consensus(block_height).unwrap(),
                                );
                            }
                        }
                    }

                    // Iterate through our UTXO set and execute an executable TX
                    // TODO: May have to respect an order here.
                    let mut remove_utxo = None;
                    for (outpoint, _) in self.utxo_set.iter() {
                        match graph.get(&outpoint) {
                            Some(connected_txs) => {
                                for tx in connected_txs {
                                    // println!("{:?}", tx);
                                    // TODO: Some of the leaves will eventually need additional unlocking data for the tapleafs
                                    // TODO: Check whether the transaction is executable
                                    match self.esplora.broadcast(tx).await {
                                        Ok(_) => {
                                            println!("Succesfully broadcasted next transaction with id: {}", tx.compute_txid());
                                            remove_utxo = Some(outpoint.clone());
                                            break;
                                        }
                                        Err(_) => (),
                                    }
                                }
                            }
                            None => continue,
                        }
                    }

                    if let Some(remove_utxo) = remove_utxo {
                        self.utxo_set.remove(&remove_utxo);
                        graph.remove(&remove_utxo);
                    }
                }
                Err(_) => {}
            }
        }
    }
}
