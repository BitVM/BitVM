use async_trait::async_trait;

use crate::constants::DestinationNetwork;

use super::chain::PegInEvent;
use super::chain::PegOutBurntEvent;
use super::chain::PegOutEvent;
use super::ethereum_adaptor::EthereumAdaptor;
use super::ethereum_adaptor::EthereumInitConfig;
use super::mock_adaptor::MockAdaptor;
use super::mock_adaptor::MockAdaptorConfig;

#[async_trait]
pub trait ChainAdaptor {
    async fn get_peg_out_init_event(&self) -> Result<Vec<PegOutEvent>, String>;
    async fn get_peg_out_burnt_event(&self) -> Result<Vec<PegOutBurntEvent>, String>;
    async fn get_peg_in_minted_event(&self) -> Result<Vec<PegInEvent>, String>;
}

pub fn get_chain_adaptor(
    network: DestinationNetwork,
    ethereum_config: Option<EthereumInitConfig>,
    mock_adaptor_config: Option<MockAdaptorConfig>,
) -> Box<dyn ChainAdaptor> {
    match network {
        DestinationNetwork::Ethereum => Box::new(EthereumAdaptor::new(ethereum_config)),
        DestinationNetwork::EthereumSepolia => Box::new(EthereumAdaptor::new(ethereum_config)),
        DestinationNetwork::Local => Box::new(MockAdaptor::new(mock_adaptor_config)),
    }
}
