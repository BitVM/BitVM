use crate::treepp::*;
use std::collections::HashMap;
use bitcoin_script_stack::stack::StackTracker;
pub use bitcoin_script::builder::StructuredScript as Script;
use crate::u4::{u4_std::u4_repeat_number};
use super::blake3_utils::*;

// final rounds: 8 => 32 bytes hash
// final rounds: 5 => 20 bytes hash (blake_160)
pub fn blake3_u4(stack: &mut StackTracker, mut msg_len: u32, final_rounds: u8) {
    assert!(
        msg_len <= 288,
        "This blake3 implementation supports up to 288 bytes"
    );

    let use_full_tables = msg_len <= 232;

    let num_blocks = msg_len.div_ceil(64);
    let mut num_padding_bytes = num_blocks * 64 - msg_len;

    //to handle the message the padding needs to be multiple of 4
    //so if it's not multiple it needs to be added at the beginning
    let mandatory_first_block_padding = num_padding_bytes % 4;
    num_padding_bytes -= mandatory_first_block_padding;

    if mandatory_first_block_padding > 0 {
        stack.custom(
            u4_repeat_number(0, (mandatory_first_block_padding) * 2),
            0,
            false,
            0,
            "padding",
        );
    }

    let mut original_message = Vec::new();
    for i in 0..msg_len / 4 {
        let m = stack.define(8, &format!("msg_{}", i));
        original_message.push(m);
    }

    for _ in original_message.iter() {
        stack.to_altstack();
    }


    let tables = TablesVars::new(stack, use_full_tables);

    for _ in original_message.iter() {
        stack.from_altstack();
    }


    //process every block
    for i in 0..num_blocks {
        let last_round = i == num_blocks - 1;
        let intermediate_rounds = if last_round { final_rounds } else { 8 };

        let flags = get_flags_for_block(i, num_blocks);

        // add the padding on the last round
        if last_round && num_padding_bytes > 0 {
            stack.custom(
                u4_repeat_number(0, (num_padding_bytes) * 2),
                0,
                false,
                0,
                "padding",
            );
            for i in 0..(num_padding_bytes / 4) {
                let m = stack.define(8, &format!("padd_{}", i));
                original_message.push(m);
            }
        }

        // create the current block message map
        let mut message = HashMap::new();
        for m in 0..16 {
            message.insert(m as u8, original_message[m + (16 * i) as usize]);
        }

        // compress the block
        compress(
            stack,
            i > 0,
            0,
            msg_len.min(64),
            flags,
            message,
            &tables,
            intermediate_rounds,
            last_round,
        );

        if msg_len > 64 {
            msg_len -= 64;
        }

        //drop the rest of the state
        for _ in 0..16 - intermediate_rounds {
            stack.drop(stack.get_var_from_stack(0));
        }

    }

    //drop tables
    tables.drop(stack);

    //get the result hash
    stack.from_altstack_joined(final_rounds as u32 * 8, "blake3-hash");
}
 

pub fn bytes_to_nibbles_blake3_output(v: Vec<u8>) -> Vec<u8> {
    v.into_iter()
        .flat_map(|b| [b >> 4, b & 0x0F])
        .collect()
}

use crate::clementine::utils::roll_constant;
/// Calculates the BLAKE3 hash of the last stack elements, in the form of nibbles
pub fn blake3_script(msg_len: u32) -> Script {
    assert!(msg_len % 4 == 0, "Byte count needs to be a multiple of four");
    let mut stack = StackTracker::new();
    blake3_u4(&mut stack, msg_len as u32, 8);
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
        { stack.get_script() }
    }
}

// This is just regular BLAKE3 with %4=0 condition
pub fn blake3_bitvm_version(v: Vec<u8>) -> [u8; 32] {
    assert!(v.len() % 4 == 0, "Byte count needs to be a multiple of four");
    blake3::hash(&v).as_bytes().clone()
}

#[cfg(test)]
mod tests {
    pub use bitcoin_script::script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use bitcoin_script_stack::{debugger::debug_script, stack::StackTracker, optimizer::optimize};

    use super::*;
    use crate::{run, u4::u4_std::u4_hex_to_nibbles};

    fn verify_blake3_hash(result: &str) -> Script {
        script! {
            { u4_hex_to_nibbles(result)}
            for _ in 0..result.len() {
                OP_TOALTSTACK
            }

            for i in 1..result.len() {
                {i}
                OP_ROLL
            }

            for _ in 0..result.len() {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }

        }
    }

    
    #[test]
    fn test_blake3_without_tracker() {
        let mut rng = ChaCha20Rng::seed_from_u64(37 as u64);
        for _ in 0..20 {
            let size = rng.gen_range(1..=25) * 4; 
            let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let result = bytes_to_nibbles_blake3_output(blake3_bitvm_version(v.clone()).to_vec());
            let s = script! {
                for x in bytes_to_nibbles_blake3_output(v) {
                    { x }
                }
                { blake3_script(size) }
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
    fn test_blake3_without_tracker_double_hash() {
        let mut rng = ChaCha20Rng::seed_from_u64(37 as u64);
        for _ in 0..20 {
            let size = rng.gen_range(1..=25) * 4; 
            let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let result = bytes_to_nibbles_blake3_output(blake3_bitvm_version(blake3_bitvm_version(v.clone()).to_vec()).to_vec());
            let s = script! {
                for x in bytes_to_nibbles_blake3_output(v) {
                    { x }
                }
                { blake3_script(size) }
                { blake3_script(32) }
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
    fn test_blake3_without_tracker_concat_hash() {
        let mut rng = ChaCha20Rng::seed_from_u64(37 as u64);
        for _ in 0..20 {
            let size = rng.gen_range(1..=25) * 4; 
            let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let add_size = rng.gen_range(1..=25) * 4;
            let add: Vec<u8> = (0..add_size).map(|_| rng.gen()).collect();
            let mut first_hash = blake3_bitvm_version(v.clone()).to_vec();
            first_hash.extend(add.clone());
            let result = bytes_to_nibbles_blake3_output(blake3_bitvm_version(first_hash).to_vec());
            let s = script! {
                for x in bytes_to_nibbles_blake3_output(v) {
                    { x }
                }
                { blake3_script(size) }
                for x in bytes_to_nibbles_blake3_output(add) {
                    { x }
                }
                { blake3_script(32 + add_size) }
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
    fn test_blake3_for_nibble_array() {
        fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
            let mut msg_bytes = Vec::with_capacity(digits.len() / 2);
        
            for nibble_pair in digits.chunks(2) {
                let byte = (nibble_pair[0] << 4) | (nibble_pair[1] & 0b00001111);
                msg_bytes.push(byte);
            }
        
            fn le_to_be_byte_array(byte_array: Vec<u8>) -> Vec<u8> {
                assert!(byte_array.len() % 4 == 0, "Byte array length must be a multiple of 4");
                byte_array
                    .chunks(4) // Process each group of 4 bytes (one u32)
                    .flat_map(|chunk| chunk.iter().rev().cloned()) // Reverse each chunk
                    .collect()
            }
            le_to_be_byte_array(msg_bytes)
        }


        let mut stack = StackTracker::new();
        let msg:Vec<u8> = vec![2, 3, 14, 5, 5, 11, 1, 4, 6, 6, 2, 0, 6, 2, 7, 11, 5, 5, 15, 10, 5, 1, 9, 2, 10, 6, 12, 9, 4, 8, 9, 14, 13, 13, 5, 10, 12, 11, 5, 12, 5, 3, 14, 15, 11, 12, 12, 12, 12, 13, 10, 11, 2, 0, 14, 9, 10, 9, 4, 4, 2, 3, 10, 15, 1, 8, 14, 13, 7, 13, 2, 12, 14, 7, 7, 15, 13, 14, 4, 6, 11, 4, 0, 15, 8, 2, 3, 1, 7, 2, 12, 1, 13, 1, 4, 5, 4, 7, 4, 6, 15, 10, 13, 11, 6, 11, 3, 8, 12, 15, 7, 1, 2, 11, 1, 14, 10, 1, 7, 13, 12, 14, 2, 9, 4, 7, 15, 13, 0, 9, 12, 13, 2, 14, 3, 9, 14, 9, 11, 12, 0, 5, 1, 2, 10, 10, 9, 12, 1, 2, 14, 0, 10, 7, 6, 1, 5, 11, 7, 8, 13, 5, 7, 7, 1, 7, 15, 11, 6, 0, 12, 4, 14, 10, 3, 2, 2, 9, 5, 5, 14, 5, 8, 1, 4, 5, 3, 1, 15, 7, 3, 15, 0, 0, 11, 15, 4, 12, 10, 10, 2, 13, 5, 5, 11, 11, 3, 9, 10, 15, 12, 13, 10, 13, 0, 10, 7, 0, 9, 9, 15, 12, 15, 11, 4, 15, 5, 12, 3, 5, 5, 12, 10, 3, 12, 13, 13, 2, 11, 4, 14, 13, 7, 5, 11, 8, 4, 5, 1, 9, 8, 10, 2, 9, 9, 15, 0, 4, 15, 4, 2, 15, 11, 7, 4, 0, 13, 1, 15, 9, 4, 11, 5, 8, 2, 15, 0, 12, 8, 14, 7, 2, 8, 9, 8, 8, 15, 11, 3, 9, 15, 9, 3, 9, 7, 10, 11, 8, 5, 0, 5, 2, 2, 0, 11, 10, 15, 14, 8, 10, 15, 15, 13, 3, 2, 8, 5, 5, 4, 13, 0, 10, 4, 14, 10, 4, 9, 1, 9, 11, 12, 1, 5, 4, 8, 10, 3, 5, 13, 10, 11, 1, 7, 7, 13, 14, 9, 5, 10, 4, 4, 9, 12, 5, 14, 12, 1, 13, 6, 10, 5, 15, 8, 5, 5, 12, 2, 11, 2, 1, 1, 2, 6, 8, 6, 13, 7, 11, 3, 7, 13, 10, 2, 11].to_vec();

        let msg_len = msg.len();


        let expected_hex_out = blake3::hash(&nib_to_byte_array(&msg)).to_string();
        println!("expected {:?}", expected_hex_out);

        let inp =  script! {
            for nibble in msg {
                { nibble }
            }
        };
        stack.custom(
            script! { { inp } },
            0,
            false,
            0,
            "msg",
        );


        let start = stack.get_script().len();
        blake3_u4(&mut stack, (msg_len/2) as u32, 8);
        let end = stack.get_script().len();
        println!("Blake3 size: {} for: {} bytes", end - start, (msg_len/2) as u32);


        stack.custom(
            script! { {verify_blake3_hash(&expected_hex_out)}},
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();
        let res =  stack.run();
        assert!(res.success);
    }

    #[test]
    fn test_blake3() {
        let hex_out = "86ca95aefdee3d969af9bcc78b48a5c1115be5d66cafc2fc106bbd982d820e70";

        let mut stack = StackTracker::new();

        let hex_in = "00000001".repeat(16);
        stack.custom(
            script! { { u4_hex_to_nibbles(&hex_in) } },
            0,
            false,
            0,
            "msg",
        );

        let start = stack.get_script().len();
        let optimized_start = optimize(stack.get_script().compile()).len();

        blake3_u4(&mut stack, 64, 8);
        let end = stack.get_script().len();
        println!("Blake3 size: {}", end - start);

        let optimized_end = optimize(stack.get_script().compile()).len();
        println!("Blake3 optimized size: {}", optimized_end - optimized_start);

        stack.custom(
            script! { {verify_blake3_hash(hex_out)}},
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();

        assert!(stack.run().success);

        //assert optimized version too
        let optimized = optimize(stack.get_script().compile());
        assert!(debug_script(optimized).0.result().unwrap().success);        

    }

    #[test]
    fn test_blake3_160() {
        let hex_out = "290eef2c4633e64835e2ea6395e9fc3e8bf459a7";

        let mut stack = StackTracker::new();

        let hex_in = "00000001".repeat(10);
        stack.custom(
            script! { { u4_hex_to_nibbles(&hex_in) } },
            0,
            false,
            0,
            "msg",
        );

        let start = stack.get_script().len();
        blake3_u4(&mut stack, 40, 5);
        let end = stack.get_script().len();
        println!("Blake3 size: {}", end - start);

        stack.custom(
            script! { {verify_blake3_hash(hex_out)}},
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();

        assert!(stack.run().success);
    }

    fn test_long_blakes(repeat: u32, hex_out: &str) {
        let mut stack = StackTracker::new();

        let hex_in = "00000001".repeat(repeat as usize);
        stack.custom(
            script! { { u4_hex_to_nibbles(&hex_in) } },
            0,
            false,
            0,
            "msg",
        );

        let start = stack.get_script().len();
        let start_optimized = optimize(stack.get_script().compile()).len();
        blake3_u4(&mut stack, repeat * 4, 8);
        let end = stack.get_script().len();
        println!("Blake3 size: {} for: {} bytes", end - start, repeat * 4);

        let end_optimized = optimize(stack.get_script().compile()).len();
        println!("Blake3 optimized size: {} for: {} bytes", end_optimized - start_optimized, repeat * 4);

        stack.custom(
            script! { {verify_blake3_hash(hex_out)}},
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_blake3_long() {
        let hex_out = "9bd93dd19a93d1d3522c6717d77a2e20e11b8627efa5df80c76d727ca7431892";
        test_long_blakes(20, hex_out);

        let hex_out = "08729d0161b725b93e83ce79b06c534ce7684d39e21ad05074b67e0ac89ef44a";
        test_long_blakes(40, hex_out);

        //limit not moving padding
        let hex_out = "f2487b9f736cc30faf28952733c95560dc60e72cc7731b03a9ecfc86665e2e85";
        test_long_blakes(48, hex_out);

        //limit full tables
        let hex_out = "034acb9761990badc714913b9bb6329d96ed91ea01530a55e8fd4c8ffb3aee42";
        test_long_blakes(57, hex_out);

        let hex_out = "a23e7a7e11ff2febf28a205c8dc0ca57ae4eb2d0eb079bb5c6a5bdcdd3e56de1";
        test_long_blakes(60, hex_out);

        //max limit
        let hex_out = "b6c1b3d6b1555e0d20bd5188e4b8b20488c36105fd9c8971ac10dd267e612e4f";
        test_long_blakes(72, hex_out);
    }
}