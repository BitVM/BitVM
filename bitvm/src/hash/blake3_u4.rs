use super::blake3::blake3_compute_script_with_limb;
use crate::treepp::*;
pub use bitcoin_script::builder::StructuredScript as Script;

pub fn bytes_to_nibbles(v: Vec<u8>) -> Vec<u8> {
    v.into_iter().flat_map(|b| [b >> 4, b & 0x0F]).collect()
}

use crate::clementine::utils::roll_constant;

fn reformat_for_blake3(msg_len: u32) -> Script {
    //assert!(msg_len <= 192);
    let padding = (64 - msg_len % 64) % 64;
    let total_len = msg_len + padding;
    script! {
        // a_0, a_1, b_0, b_1, c_0, c_1, d_0, d_1 =>  d_0, d_1, c_0, c_1, b_0, b_1, a_0, a_1
        for _ in 0..(msg_len / 4) {
            { roll_constant(6) } OP_TOALTSTACK
            { roll_constant(6) } OP_TOALTSTACK
            { roll_constant(4) } OP_TOALTSTACK
            { roll_constant(4) } OP_TOALTSTACK
            { roll_constant(2) } OP_TOALTSTACK
            { roll_constant(2) } OP_TOALTSTACK
            { roll_constant(0) } OP_TOALTSTACK
            { roll_constant(0) } OP_TOALTSTACK
        }
        for _ in 0..(msg_len * 2) {
            OP_FROMALTSTACK
        }
        for i in 0..padding {
            if i == 0 {
                OP_0 OP_0
            } else {
                OP_2DUP
            }
        }
        // Reverse the 64 chunks because compact wants it
        for i in (0..(total_len / 64 - 1)).rev() {
            for _ in 0..128 {
                { roll_constant((total_len - i * 64) as usize * 2 - 1) }
            }
        }
    }
}

/// Calculates the BLAKE3 hash of the last stack elements, in the form of nibbles
pub fn blake3_u4_script(msg_len: u32) -> Script {
    assert!(
        msg_len % 4 == 0,
        "Byte count needs to be a multiple of four"
    );
    script! {
        { reformat_for_blake3(msg_len)  }
        { blake3_compute_script_with_limb(msg_len as usize, 4) }
    }
}

// This is just regular BLAKE3 with %4=0 condition
pub fn blake3_bitvm_version(v: Vec<u8>) -> [u8; 32] {
    assert!(
        v.len() % 4 == 0,
        "Byte count needs to be a multiple of four"
    );
    *blake3::hash(&v).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::blake3::blake3_push_message_script_with_limb;
    pub use bitcoin_script::script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_foo() {
        let mut rng = ChaCha20Rng::seed_from_u64(37 as u64);
        let size = 120;
        let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        assert!(
            execute_script(script! {
                for x in bytes_to_nibbles(v.clone()) {
                    { x }
                }
                { reformat_for_blake3(size) }
                { blake3_push_message_script_with_limb(&v, 4) }
                for i in (1..256).rev() {
                    { i + 1 } OP_ROLL OP_EQUALVERIFY
                }
                OP_EQUAL
            })
            .success
        );
    }

    #[test]
    fn test_blake3_u4() {
        let mut rng = ChaCha20Rng::seed_from_u64(37 as u64);
        for i in 15..=15 {
            let size = i * 4;
            let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let result = bytes_to_nibbles(blake3_bitvm_version(v.clone()).to_vec());
            let s = script! {
                for x in bytes_to_nibbles(v.clone()) {
                    { x }
                }
                { blake3_u4_script(size as u32) }
                for i in (0..64).rev() {
                    { result[i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(s)
        }
    }

    #[test]
    fn test_blake3_u4_double_hash() {
        let mut rng = ChaCha20Rng::seed_from_u64(37 as u64);
        for i in 1..=25 {
            let size = i * 4;
            let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let result = bytes_to_nibbles(
                blake3_bitvm_version(blake3_bitvm_version(v.clone()).to_vec()).to_vec(),
            );
            let s = script! {
                for x in bytes_to_nibbles(v) {
                    { x }
                }
                { blake3_u4_script(size) }
                { blake3_u4_script(32) }
                for i in (0..64).rev() {
                    { result[i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(s)
        }
    }

    #[test]
    fn test_blake3_u4_concat_hash() {
        let mut rng = ChaCha20Rng::seed_from_u64(37 as u64);
        for _ in 0..20 {
            let size = rng.gen_range(1..=25) * 4;
            let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let add_size = rng.gen_range(1..=25) * 4;
            let add: Vec<u8> = (0..add_size).map(|_| rng.gen()).collect();
            let mut first_hash = blake3_bitvm_version(v.clone()).to_vec();
            first_hash.extend(add.clone());
            let result = bytes_to_nibbles(blake3_bitvm_version(first_hash).to_vec());
            let s = script! {
                for x in bytes_to_nibbles(v) {
                    { x }
                }
                { blake3_u4_script(size) }
                for x in bytes_to_nibbles(add) {
                    { x }
                }
                { blake3_u4_script(32 + add_size) }
                for i in (0..64).rev() {
                    { result[i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(s)
        }
    }
}
