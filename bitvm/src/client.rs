use std::{collections::HashMap, str::FromStr, thread::sleep, time::Duration, borrow::BorrowMut};
use bitcoin::OutPoint;
use esplora_client::{BlockHash, Builder, Transaction, Txid};
use tapscripts::actor::{Player, Opponent};
use crate::{graph::{CompiledBitVMGraph}, model::BitVmModel};

pub struct BitVMClient {
    // actor_id: Role,
    utxo_set: HashMap<(Txid, u32), u32>
}


impl BitVMClient {
    pub fn new() -> Self {
        Self { utxo_set: HashMap::new() }
    }

    pub async fn listen(&mut self, model: &mut BitVmModel, graph: &CompiledBitVMGraph ) {
        // TODO: Set opponent
        let builder = Builder::new("https://mutinynet.com/api");
        let esplora = builder.build_async().unwrap();
        let mut latest_hash =
            BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap();
        let utxo_set = &mut self.utxo_set;

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
                        // TODO: Check if this transaction belongs to our graph
                        
                        // Read the commited values from transaction
                        // model.opponent.witness_tx(&tx);
                        
                        
                        // Update our UTXO set
                        update_utxo_set(utxo_set, tx, block_height);
                    }

                    // Iterate through our UTXO set and execute the first executable TX
                    for utxo in utxo_set.into_iter() {
                        let (output, _block_height) = utxo;
                        let outpoint = OutPoint{ txid: output.0, vout: output.1 };
                        
                        match graph.get(&outpoint){
                            Some(children) => {
                                for tx in children {
                                    println!("{:?}", tx);
                                    // try execute the TX
                                    // iterate through the TX's leaves and try to execute them
                                }
                            },
                            None => continue
                        }

                        // const &utxo = this.utxoSet[txid]
                        // const utxoAge = block.height - utxo.blockHeight
                        // for(const nextTx of this.graph[txid]){
                        //     const success = await nextTx.tryExecute(this.actorId, utxoAge)
                        //     if(success)
                        //         return
                        // }
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
