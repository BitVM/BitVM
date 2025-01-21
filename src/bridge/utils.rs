use bitcoin::Network;

const NUM_BLOCKS_REGTEST: u32 = 3;
const NUM_BLOCKS_TESTNET: u32 = 3;

pub fn num_blocks_per_network(network: Network, mainnet_num_blocks: u32) -> u32 {
    match network {
        Network::Bitcoin => mainnet_num_blocks,
        Network::Regtest => NUM_BLOCKS_REGTEST,
        _ => NUM_BLOCKS_TESTNET, // Testnet, Signet
    }
}

pub fn remove_script_and_control_block_from_witness(mut witness: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    witness.truncate(witness.len() - 2);

    witness
}
