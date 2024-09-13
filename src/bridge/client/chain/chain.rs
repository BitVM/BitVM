use bitcoin::{Amount, OutPoint, PubkeyHash, PublicKey};

use super::{
    base::ChainAdaptor,
    ethereum::{EthereumAdaptor, EthereumInitConfig},
};

#[derive(Debug)]
pub struct PegOutEvent {
    pub withdrawer_chain_address: String,
    pub withdrawer_public_key_hash: PubkeyHash,
    pub source_outpoint: OutPoint,
    pub amount: Amount,
    pub operator_public_key: PublicKey,
    pub timestamp: u32,
}

#[derive(Debug)]
pub struct PegOutBurntEvent {
    pub withdrawer_chain_address: String,
    pub source_outpoint: OutPoint,
    pub amount: Amount,
    pub operator_public_key: PublicKey,
    pub timestamp: u32,
}

#[derive(Debug)]
pub struct PegInEvent {
    pub depositor: String,
    pub amount: Amount,
    pub depositor_pubkey: PublicKey,
}

static CLIENT_MISSING_ORACLE_DRIVER_ERROR: &str = "Bridge client is missing chain adaptor";

pub struct Chain {
    ethereum: Option<EthereumAdaptor>,
}

impl Chain {
    pub fn new() -> Self {
        Self {
            ethereum: EthereumAdaptor::new(),
        }
    }

    pub fn init_ethereum(&mut self, conf: EthereumInitConfig) {
        self.ethereum = Some(EthereumAdaptor::from_config(conf));
    }

    pub async fn get_peg_out_init(&self) -> Result<Vec<PegOutEvent>, String> {
        match self.get_driver() {
            Ok(driver) => match driver.get_peg_out_init_event().await {
                Ok(events) => Ok(events),
                Err(err) => Err(err.to_string()),
            },
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn get_peg_in_minted(&self) -> Result<Vec<PegInEvent>, String> {
        match self.get_driver() {
            Ok(driver) => driver.get_peg_in_minted_event().await,
            Err(err) => Err(err.to_string()),
        }
    }

    fn get_driver(&self) -> Result<&dyn ChainAdaptor, &str> {
        if self.ethereum.is_some() {
            return Ok(self.ethereum.as_ref().unwrap());
        } else {
            Err(CLIENT_MISSING_ORACLE_DRIVER_ERROR)
        }
    }
}
