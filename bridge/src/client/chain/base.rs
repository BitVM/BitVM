use async_trait::async_trait;

use super::chain::PegInEvent;
use super::chain::PegOutBurntEvent;
use super::chain::PegOutEvent;

#[async_trait]
pub trait ChainAdaptor {
    async fn get_peg_out_init_event(&self) -> Result<Vec<PegOutEvent>, String>;
    async fn get_peg_out_burnt_event(&self) -> Result<Vec<PegOutBurntEvent>, String>;
    async fn get_peg_in_minted_event(&self) -> Result<Vec<PegInEvent>, String>;
}
