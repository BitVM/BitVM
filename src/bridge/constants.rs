use core::fmt;

//TODO: replace with real value, and delete this comment
// pub const NUM_BLOCKS_PER_WEEK: u32 = 1008;
pub const NUM_BLOCKS_PER_WEEK: u32 = 1;
pub const NUM_BLOCKS_PER_2_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 2;
pub const NUM_BLOCKS_PER_4_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 4;

#[derive(Eq, PartialEq, Clone, Copy)]
pub enum DestinationNetwork {
    /// Mainnet Ethereum.
    Ethereum,
    /// Ethereum's testnet network.
    EthereumSepolia,
}

impl fmt::Display for DestinationNetwork {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use DestinationNetwork::*;

        let s = match *self {
            Ethereum => "ethereum",
            EthereumSepolia => "ethereum_sepolia",
        };
        write!(f, "{}", s)
    }
}
