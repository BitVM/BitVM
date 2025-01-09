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
            1229263625, 3554575280, 757801727, 1044199622, 41871057, 2230985017, 1106344398,
            1365079968,
        ],
        Some(network) if matches!(network.as_bytes(), b"testnet4") => [
            265150045, 1271856006, 398824233, 651953322, 2318550887, 1708731876, 396859917,
            1558582092,
        ],
        Some(network) if matches!(network.as_bytes(), b"signet") => [
            1022064097, 2996254829, 1663776000, 2377717666, 439263173, 455603496, 1186387195,
            446545343,
        ],
        Some(network) if matches!(network.as_bytes(), b"regtest") => [
            2616857078, 2160837996, 2922182214, 1949433138, 1244749737, 661008797, 91599062,
            2562114807,
        ],
        None => [
            1229263625, 3554575280, 757801727, 1044199622, 41871057, 2230985017, 1106344398,
            1365079968,
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
