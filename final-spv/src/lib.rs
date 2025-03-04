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
            1025221519,
            1687105276,
            3611665327,
            557184943,
            2180189937,
            3348777746,
            788706614,
            1004332989,
        ],
        Some(network) if matches!(network.as_bytes(), b"testnet4") => [
            150832604,
            3183129632,
            1629542105,
            1261053925,
            3494018259,
            1702793780,
            1762938269,
            2146070154,
        ],
        Some(network) if matches!(network.as_bytes(), b"signet") => [
            2951985855,
            3401492476,
            1212031557,
            627934036,
            2564778263,
            3861960932,
            2219059336,
            1747235921,
        ],
        Some(network) if matches!(network.as_bytes(), b"regtest") => [
            2809155365,
            2479136856,
            4179744211,
            793384048,
            380824505,
            1917194500,
            2106887245,
            3328631047,
        ],
        None => [
            1025221519,
            1687105276,
            3611665327,
            557184943,
            2180189937,
            3348777746,
            788706614,
            1004332989,
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
