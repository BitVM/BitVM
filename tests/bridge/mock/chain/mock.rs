use async_trait::async_trait;
use bitvm::bridge::client::chain::{
    base::ChainAdaptor,
    chain::{PegInEvent, PegOutBurntEvent, PegOutEvent},
};

pub struct MockAdaptor {
    pub peg_out_init_events: Vec<PegOutEvent>,
    pub peg_out_burnt_events: Vec<PegOutBurntEvent>,
    pub peg_in_minted_events: Vec<PegInEvent>,
}

#[async_trait]
impl ChainAdaptor for MockAdaptor {
    async fn get_peg_out_init_event(&self) -> Result<Vec<PegOutEvent>, String> {
        Ok(self.peg_out_init_events.clone())
    }

    async fn get_peg_out_burnt_event(&self) -> Result<Vec<PegOutBurntEvent>, String> {
        Ok(self.peg_out_burnt_events.clone())
    }

    async fn get_peg_in_minted_event(&self) -> Result<Vec<PegInEvent>, String> {
        Ok(self.peg_in_minted_events.clone())
    }
}

impl MockAdaptor {
    pub fn new() -> Self {
        Self {
            peg_out_init_events: vec![],
            peg_out_burnt_events: vec![],
            peg_in_minted_events: vec![],
        }
    }

    pub fn from_peg_out_init(peg_out_init_events: Vec<PegOutEvent>) -> Self {
        Self {
            peg_out_init_events,
            peg_out_burnt_events: vec![],
            peg_in_minted_events: vec![],
        }
    }
}
