use async_trait::async_trait;

use super::{
    chain::{PegInEvent, PegOutBurntEvent, PegOutEvent},
    chain_adaptor::ChainAdaptor,
};

pub struct MockAdaptor {
    config: Option<MockAdaptorConfig>,
}

pub struct MockAdaptorConfig {
    pub peg_out_init_events: Option<Vec<PegOutEvent>>,
    pub peg_out_burnt_events: Option<Vec<PegOutBurntEvent>>,
    pub peg_out_minted_events: Option<Vec<PegInEvent>>,
}

impl MockAdaptor {
    pub fn new(config: Option<MockAdaptorConfig>) -> Self { Self { config } }
}

#[async_trait]
impl ChainAdaptor for MockAdaptor {
    async fn get_peg_out_init_event(&self) -> Result<Vec<PegOutEvent>, String> {
        if let Some(_config) = &self.config {
            if let Some(_init_events) = &_config.peg_out_init_events {
                return Ok(_init_events.clone());
            }
        }

        Ok(vec![])
    }

    async fn get_peg_out_burnt_event(&self) -> Result<Vec<PegOutBurntEvent>, String> {
        if let Some(_config) = &self.config {
            if let Some(_burnt_events) = &_config.peg_out_burnt_events {
                return Ok(_burnt_events.clone());
            }
        }

        Ok(vec![])
    }
    async fn get_peg_in_minted_event(&self) -> Result<Vec<PegInEvent>, String> {
        if let Some(_config) = &self.config {
            if let Some(_minted_events) = &_config.peg_out_minted_events {
                return Ok(_minted_events.clone());
            }
        }

        Ok(vec![])
    }
}
