use bitcoin::{block::Header, consensus::encode::serialize, hashes::Hash, BlockHash};

use crate::signatures::winternitz::bytes_to_digits;

/*
  TODO: Implement selecting a block that marks the start of a superblock measurement period
  that lasts for the period ∆C (e.g. 2000 blocks), during which the operator must observe
  all blocks on the main chain and identify the heaviest superblock SB.
*/
pub fn get_start_time_block_number() -> u32 { return 860033; }

pub fn find_superblock() -> Header { todo!() }

pub fn get_superblock_message_digits(sb: &Header) -> Vec<u8> { bytes_to_digits(&serialize(sb)) }

pub const SUPERBLOCK_MESSAGE_LENGTH_IN_DIGITS: usize = size_of::<Header>() * 2; // For 4-bit digits

pub fn get_superblock_hash_message_digits(sb: &Header) -> Vec<u8> {
    bytes_to_digits(sb.block_hash().as_byte_array())
}

pub const SUPERBLOCK_HASH_MESSAGE_LENGTH_IN_DIGITS: usize = size_of::<BlockHash>() * 2; // For 4-bit digits
