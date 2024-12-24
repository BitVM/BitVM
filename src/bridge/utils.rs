use bitcoin::Network;

const NUM_BLOCKS_REGTEST: u32 = 3;
const NUM_BLOCKS_TESTNET: u32 = 0;

pub fn num_blocks_per_network(network: Network, mainnet_num_blocks: u32) -> u32 {
    match network {
        Network::Bitcoin => mainnet_num_blocks,
        Network::Regtest => NUM_BLOCKS_REGTEST,
        _ => NUM_BLOCKS_TESTNET, // Testnet, Signet
    }
}
