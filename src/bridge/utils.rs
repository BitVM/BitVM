use bitcoin::Network;

use super::constants::{NUM_BLOCKS_PER_2_WEEKS, NUM_BLOCKS_PER_4_WEEKS};

pub fn get_num_blocks_per_2_weeks(network: Network) -> u32 {
    if network == Network::Bitcoin {
        return NUM_BLOCKS_PER_2_WEEKS;
    } else {
        return 1;
    }
}

pub fn get_num_blocks_per_4_weeks(network: Network) -> u32 {
    if network == Network::Bitcoin {
        return NUM_BLOCKS_PER_4_WEEKS;
    } else {
        return 1;
    }
}
