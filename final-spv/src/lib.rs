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
            1089137192, 2499827081, 1648551528, 3898441744, 1241508107, 1212614376, 523594555,
            2385906108,
        ],
        Some(network) if matches!(network.as_bytes(), b"testnet4") => [
            1866422223, 3011666006, 1737793548, 1848006863, 1320341210, 1623031594, 1418162769,
            4138395741,
        ],
        Some(network) if matches!(network.as_bytes(), b"signet") => [
            3760542186, 3452311364, 636757141, 2341919608, 3798837687, 3808746669, 4002435111,
            318058396,
        ],
        Some(network) if matches!(network.as_bytes(), b"regtest") => [
            1361809821, 2352021461, 2194279832, 977027345, 356844560, 3592195208, 1085394392,
            1717039563,
        ],
        None => [
            1089137192, 2499827081, 1648551528, 3898441744, 1241508107, 1212614376, 523594555,
            2385906108,
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
