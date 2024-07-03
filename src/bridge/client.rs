use std::{collections::HashMap, str::FromStr, thread::sleep, time::Duration};

use bitcoin::{absolute::Height, Address, Amount, OutPoint};
use esplora_client::{AsyncClient, BlockHash, Builder, Utxo};

use super::{contexts::base::BaseContext, graph::CompiledBitVMGraph};

const ESPLORA_URL: &str = "https://mutinynet.com/api";

pub type UtxoSet = HashMap<OutPoint, Height>;

pub struct BitVMClient {
    // Maps OutPoints to their (potentially unconfirmed) UTXOs.
    pub utxo_set: UtxoSet,
    pub esplora: AsyncClient,
}

impl Default for BitVMClient {
    fn default() -> Self { Self::new() }
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

    pub async fn get_initial_utxo(&self, address: Address, amount: Amount) -> Option<Utxo> {
        let utxos = self.esplora.get_address_utxo(address).await.unwrap();
        let possible_utxos = utxos
            .into_iter()
            .filter(|utxo| utxo.value == amount)
            .collect::<Vec<_>>();
        if !possible_utxos.is_empty() {
            Some(possible_utxos[0].clone())
        } else {
            None
        }
    }

    pub async fn get_initial_utxos(&self, address: Address, amount: Amount) -> Option<Vec<Utxo>> {
        let utxos = self.esplora.get_address_utxo(address).await.unwrap();
        let possible_utxos = utxos
            .into_iter()
            .filter(|utxo| utxo.value == amount)
            .collect::<Vec<_>>();
        if !possible_utxos.is_empty() {
            Some(possible_utxos)
        } else {
            None
        }
    }

    pub async fn execute_possible_txs(
        &mut self,
        context: &dyn BaseContext,
        graph: &mut CompiledBitVMGraph,
    ) {
        // Iterate through our UTXO set and execute an executable TX
        // TODO: May have to respect an order here.
        let mut remove_utxo = None;
        for (outpoint, _) in self.utxo_set.iter() {
            match graph.get(outpoint) {
                Some(subsequent_txs) => {
                    for bridge_transaction in subsequent_txs {
                        // TODO: Check whether the transaction is executable
                        let tx = bridge_transaction.finalize();
                        match self.esplora.broadcast(&tx).await {
                            Ok(_) => {
                                println!(
                                    "Succesfully broadcast next transaction with id: {}",
                                    tx.compute_txid()
                                );
                                remove_utxo = Some(*outpoint);
                                break;
                            }
                            Err(err) => panic!("Tx Broadcast Error: {}", err),
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

    pub async fn listen(
        &mut self,
        context: &dyn BaseContext,
        initial_outpoint: OutPoint,
        graph: &mut CompiledBitVMGraph,
    ) {
        let builder = Builder::new(ESPLORA_URL);
        let esplora = builder.build_async().unwrap();
        let mut latest_hash =
            BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        self.utxo_set.insert(initial_outpoint, Height::ZERO);

        while !graph.is_empty() {
            if let Ok(block_hash) = esplora.get_tip_hash().await {
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
                            self.utxo_set
                                .insert(outpoint, Height::from_consensus(block_height).unwrap());
                        }
                    }
                }
                self.execute_possible_txs(context, graph).await;
            }
        }
    }
}
