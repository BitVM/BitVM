use std::{mem::size_of, str::FromStr};

use bitcoin::{
    block::{Header, Version},
    consensus::encode::serialize,
    hashes::Hash,
    BlockHash, CompactTarget, Network, TxMerkleNode,
};
use bitcoin_script::{script, Script};

use bitvm::pseudo::NMUL;

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

// TODO: Replace with a real superblock
pub fn find_superblock() -> Header {
    Header {
        version: Version::from_consensus(0x200d2000),
        prev_blockhash: BlockHash::from_str(
            "000000000000000000027c9f5b07f21e39ba31aa4d900d519478bdac32f4a15d",
        )
        .unwrap(),
        merkle_root: TxMerkleNode::from_str(
            "0064b0d54f20412756ba7ce07b0594f3548b06f2dad5cfeaac2aca508634ed19",
        )
        .unwrap(),
        time: 1729251961,
        bits: CompactTarget::from_hex("0x17030ecd").unwrap(),
        nonce: 0x400e345c,
    }
}

pub fn get_superblock_message(sb: &Header) -> Vec<u8> {
    serialize(sb)
}

pub const SUPERBLOCK_MESSAGE_LENGTH: usize = size_of::<Header>();

pub fn get_superblock_hash_message(sb: &Header) -> Vec<u8> {
    sb.block_hash().as_byte_array().into()
}

pub const SUPERBLOCK_HASH_MESSAGE_LENGTH: usize = size_of::<BlockHash>();

pub fn extract_superblock_ts_from_header() -> Script {
    script! {
        for i in 0..4 { { 80 - 12 + 2 * i } OP_PICK }
        for _ in 1..4 {  { NMUL(1 << 8) } OP_ADD }
    }
}
