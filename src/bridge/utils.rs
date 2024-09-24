use bitcoin::Network;

pub fn num_blocks_per_network(network: Network, mainnet_num_blocks: u32) -> u32 {
    if network == Network::Bitcoin {
        mainnet_num_blocks
    } else {
        1
    }
}

/*
  TODO: Implement selecting a block that marks the start of a superblock measurement period
  that lasts for the period ∆C (e.g. 2000 blocks), during which the operator must observe
  all blocks on the main chain and identify the heaviest superblock SB.
*/
pub fn get_start_time_block() -> u32 { return 860033; }
