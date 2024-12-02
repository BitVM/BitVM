use core::fmt;

pub const NUM_BLOCKS_PER_HOUR: u32 = 6;
pub const NUM_BLOCKS_PER_6_HOURS: u32 = NUM_BLOCKS_PER_HOUR * 6;

pub const NUM_BLOCKS_PER_DAY: u32 = NUM_BLOCKS_PER_HOUR * 24;
pub const NUM_BLOCKS_PER_3_DAYS: u32 = NUM_BLOCKS_PER_DAY * 3;

pub const NUM_BLOCKS_PER_WEEK: u32 = NUM_BLOCKS_PER_DAY * 7;
pub const NUM_BLOCKS_PER_2_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 2;
pub const NUM_BLOCKS_PER_4_WEEKS: u32 = NUM_BLOCKS_PER_WEEK * 4;

pub const N_SEQUENCE_FOR_LOCK_TIME: u32 = 0xFFFFFFFE; // The nSequence field must be set to less than 0xffffffff, usually 0xffffffff-1 to avoid confilcts with relative timelocks.

//// Commitment message parameters. Hardcoded for 4-bit digits.
//const ETHEREUM_TXID_LENGTH_IN_DIGITS: usize = 64;
//const BITCOIN_TXID_LENGTH_IN_DIGITS: usize = 64;
//pub const SOURCE_NETWORK_TXID_LENGTH_IN_DIGITS: usize = BITCOIN_TXID_LENGTH_IN_DIGITS;
//pub const DESTINATION_NETWORK_TXID_LENGTH_IN_DIGITS: usize = ETHEREUM_TXID_LENGTH_IN_DIGITS;

// Commitment message parameters. Hardcoded number of bytes per message.
pub const START_TIME_MESSAGE_LENGTH: usize = 4;
const ETHEREUM_TXID_LENGTH: usize = 64;
const BITCOIN_TXID_LENGTH: usize = 64;
pub const SOURCE_NETWORK_TXID_LENGTH: usize = BITCOIN_TXID_LENGTH;
pub const DESTINATION_NETWORK_TXID_LENGTH: usize = ETHEREUM_TXID_LENGTH;

#[derive(Eq, PartialEq, Clone, Copy)]
pub enum DestinationNetwork {
    /// Mainnet Ethereum.
    Ethereum,
    /// Ethereum's testnet network.
    EthereumSepolia,
    /// Locally hosted network.
    Local,
}

impl fmt::Display for DestinationNetwork {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use DestinationNetwork::*;

        let s = match *self {
            Ethereum => "ethereum",
            EthereumSepolia => "ethereum_sepolia",
            Local => "anvil_831337",
        };
        write!(f, "{}", s)
    }
}
