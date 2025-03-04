use final_circuit::FinalCircuitInput;
use risc0_zkvm::guest::env;
use zkvm::ZkvmGuest;

pub mod final_circuit;
pub mod merkle_tree;
pub mod spv;
pub mod transaction;
pub mod utils;
pub mod zkvm;
pub use risc0_zkvm;

/// The method ID for the header chain circuit.
const HEADER_CHAIN_GUEST_ID: [u32; 8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => [
            4046644471, 903675258, 1380784752, 882266853, 3151729575, 835580507, 2476016657,
            1610521255,
        ],
        Some(network) if matches!(network.as_bytes(), b"testnet4") => [
            2421631365, 3264974484, 821027839, 1335612179, 1295879179, 713845602, 1229060261,
            258954137,
        ],
        Some(network) if matches!(network.as_bytes(), b"signet") => [
            3853738632, 3158955590, 3791151038, 2143196696, 56017613, 2356936109, 2685546689,
            1284489822,
        ],
        Some(network) if matches!(network.as_bytes(), b"regtest") => [
            1058249551, 988828560, 601998926, 732987198, 1919237144, 863935989, 2017405856,
            3942537225,
        ],
        None => [
            4046644471, 903675258, 1380784752, 882266853, 3151729575, 835580507, 2476016657,
            1610521255,
        ],
        _ => panic!("Invalid network type"),
    }
};

/// The final circuit that verifies the output of the header chain circuit.
pub fn final_circuit(guest: &impl ZkvmGuest) {
    let start = env::cycle_count();
    let input: FinalCircuitInput = guest.read_from_host::<FinalCircuitInput>();
    guest.verify(HEADER_CHAIN_GUEST_ID, &input.block_header_circuit_output);
    input.spv.verify(
        input
            .block_header_circuit_output
            .chain_state
            .block_hashes_mmr,
    );
    let mut hasher = blake3::Hasher::new();

    hasher.update(&input.spv.transaction.txid());
    hasher.update(
        &input
            .block_header_circuit_output
            .chain_state
            .best_block_hash,
    );
    hasher.update(&input.block_header_circuit_output.chain_state.total_work);
    let final_output = hasher.finalize();
    guest.commit(final_output.as_bytes());
    let end = env::cycle_count();
    println!("Final circuit took {:?} cycles", end - start);
}
