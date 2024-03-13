use std::{collections::HashMap, str::FromStr, thread::sleep, time::Duration};

use super::constants::Role;
use crate::scripts::actor::Player;
use esplora_client::{BlockHash, Builder, Transaction, Tx, Txid};

pub struct BitVMClient {
    //vicky: Player,
    //paul: Player,
    //actor_id: Role,
    utxo_set: HashMap<(Txid, u32), u32>
}


impl BitVMClient {
    pub fn new() -> Self {
        Self { utxo_set: HashMap::new() }
    }

    pub async fn listen(&mut self) {
        // TODO: Set opponent
        let builder = Builder::new("https://mutinynet.com/api");
        let esplora = builder.build_async().unwrap();
        let mut latest_hash =
            BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap();

        loop {
            match esplora.get_tip_hash().await {
                Ok(block_hash) => {
                    if block_hash == latest_hash {
                        sleep(Duration::from_secs(10));
                        continue;
                    }
                    latest_hash = block_hash;
                    // TODO: This kind of assumes that the tip did not increase. There should be a
                    // better API endpoint like /block-height/{block_hash}
                    let block_height = esplora.get_height().await.unwrap();
                    let block = esplora.get_block_by_hash(&block_hash).await.unwrap().unwrap();

                    // Handle new block received logic
                    println!("Received block {}", block_hash);
                    
                    for tx in block.txdata {
                        // TODO: Check if tx is in graph
                        self.update_utxo_set(tx, block_height);
                    }
                }
                Err(_) => {}
            }
        }
    }

    fn update_utxo_set(& mut self, tx: Transaction, block_height: u32) {
        println!("Utxo set: {:?}", self.utxo_set);
        for input in &tx.input {
            self.utxo_set.remove(&(input.previous_output.txid, input.previous_output.vout));
        }
        // Register all vouts of the transaction
        for (i, vout) in tx.output.iter().enumerate() {
            
            // TODO: Check if the vout is used by the current Player in the graph
            let txid = tx.txid();
            self.utxo_set.insert((txid, i as u32), block_height);
        }
    }
}
