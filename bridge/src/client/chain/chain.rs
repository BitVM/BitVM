use bitcoin::{Amount, OutPoint, PubkeyHash, PublicKey};
use serde::{Deserialize, Serialize};

use super::{chain_adaptor::ChainAdaptor, mock_adaptor::MockAdaptor};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct PegOutEvent {
    pub withdrawer_chain_address: String,
    pub withdrawer_destination_address: String,
    pub withdrawer_public_key_hash: PubkeyHash,
    pub source_outpoint: OutPoint,
    pub amount: Amount,
    pub operator_public_key: PublicKey,
    pub timestamp: u32,
    pub tx_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct PegOutBurntEvent {
    pub withdrawer_chain_address: String,
    pub source_outpoint: OutPoint,
    pub amount: Amount,
    pub operator_public_key: PublicKey,
    pub timestamp: u32,
    pub tx_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct PegInEvent {
    pub depositor: String,
    pub amount: Amount,
    pub depositor_pubkey: PublicKey,
}

pub struct Chain {
    adaptor: Box<dyn ChainAdaptor>,
}

impl Default for Chain {
    fn default() -> Self { Self::new(Box::new(MockAdaptor::new(None))) }
}

impl Chain {
    pub fn new(adaptor: Box<dyn ChainAdaptor>) -> Self { Self { adaptor } }

    pub async fn get_peg_out_init(&self) -> Result<Vec<PegOutEvent>, String> {
        match self.adaptor.get_peg_out_init_event().await {
            Ok(events) => Ok(events),
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn get_peg_out_burnt(&self) -> Result<Vec<PegOutBurntEvent>, String> {
        match self.adaptor.get_peg_out_burnt_event().await {
            Ok(events) => Ok(events),
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn get_peg_in_minted(&self) -> Result<Vec<PegInEvent>, String> {
        self.adaptor.get_peg_in_minted_event().await
    }
}
