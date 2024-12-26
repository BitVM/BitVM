use std::mem::size_of;

use bitcoin::{block::Header, consensus::encode::serialize, hashes::Hash, BlockHash, Network};

/*
  TODO: Implement selecting a block that marks the start of a superblock measurement period
  that lasts for the period ∆C (e.g. 2000 blocks), during which the operator must observe
  all blocks on the main chain and identify the heaviest superblock SB.
*/
pub fn get_start_time_block_number(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 161249,
        Network::Regtest => 100,
        _ => 161249,
    }
}

pub fn find_superblock() -> Header { todo!() }

pub fn get_superblock_message(sb: &Header) -> Vec<u8> { serialize(sb) }

pub const SUPERBLOCK_MESSAGE_LENGTH: usize = size_of::<Header>();

pub fn get_superblock_hash_message(sb: &Header) -> Vec<u8> {
    sb.block_hash().as_byte_array().into()
}

pub const SUPERBLOCK_HASH_MESSAGE_LENGTH: usize = size_of::<BlockHash>();
