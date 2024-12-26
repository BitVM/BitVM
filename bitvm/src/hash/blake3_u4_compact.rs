use std::collections::HashMap;

use bitcoin_script_stack::stack::StackTracker;

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;

use crate::bigint::U254;

use crate::hash::blake3_u4::{compress, get_flags_for_block, TablesVars};

// The define var is used to ensure that the message is in the form of StackVariable.
pub fn blake3_u4_compact(
    stack: &mut StackTracker,
    msg_len: u32,
    define_var: bool,
    use_full_tables: bool,
) {
    // we require that the msg_len be a multiple of 64 bytes, this makes padding unnecessary
    assert!(
        msg_len % 64 == 0,
        "msg length is not a multiple of 64 bytes"
    );

    // We require message take atmost a chunk. i.e, 1024 bytes.
    // Currently hash of empty string is not supported. I guess we could just hardcode and return the value
    assert!(
        msg_len > 0 && msg_len <= 1024,
        "msg length must be greater than 0 and less than or equal to 1024 bytes"
    );

    //number of msg blocks
    let num_blocks = msg_len / 64;

    // If the compact form of message is on stack but not associated with variable, convert it to StackVariable
    if define_var {
        for i in (0..num_blocks).rev() {
            stack.define(9, &format!("msg{}p0", i));
            stack.define(9, &format!("msg{}p1", i));
        }
    }

    // Push msg to alt stack to get the table on top
    for _ in 0..num_blocks {
        stack.to_altstack();
        stack.to_altstack();
    }

    //initialize the tables
    let tables = TablesVars::new(stack, use_full_tables);

    // pop the message from the alt stack
    for _ in 0..num_blocks {
        stack.from_altstack();
        stack.from_altstack();
    }

    //process each msg_block
    for i in 0..num_blocks {
        // unpack the compact form of message
        stack.custom(
            script!(
                {U254::unpack_limbs::<4>()}
                for _ in 0..64{
                    OP_TOALTSTACK
                }
            ),
            1,
            false,
            0,
            &format!("unpack msg{}p1", i),
        );

        stack.custom(
            script!(
                {U254::unpack_limbs::<4>()}
                for _ in 0..64{
                    OP_FROMALTSTACK
                }
            ),
            1,
            false,
            0,
            &format!("unpack msg{}p0", i),
        );

        //make a hashmap of msgs
        let mut original_message = Vec::new();
        for i in 0..16 {
            let m = stack.define(8, &format!("msg_{}", i));
            original_message.push(m);
        }

        // create the current block message map
        let mut message = HashMap::new();
        for m in 0..16 {
            message.insert(m as u8, original_message[m as usize]);
        }

        compress(
            stack,
            i != 0,
            0,
            64,
            get_flags_for_block(i, num_blocks),
            message,
            &tables,
            8,
            i == num_blocks - 1,
        );

        //delete the intermediate states
        for _ in 0..8 {
            stack.drop(stack.get_var_from_stack(0));
        }
    }
    // drop tables
    tables.drop(stack);

    // get the result hash
    stack.from_altstack_joined(8 as u32 * 8, "blake3-hash");
}

#[cfg(test)]
mod tests {

    pub use bitcoin_script::script;
    use bitcoin_script_stack::{debugger::debug_script, optimizer::optimize, stack::StackTracker};
    use num_traits::ToBytes;
    use rand::Rng;

    use super::*;
    use crate::{execute_script, u4::u4_std::u4_hex_to_nibbles};

    // verfires that the hash of the input hex matches with the official implementation.
    // can also be verified using https://emn178.github.io/online-tools/blake3/?input=<input_hex_str>
    fn test_blake3_compact_giveninputhex(input_hex_str: String) {
        // message length in bytes
        let msg_len: u32 = (input_hex_str.len() / 2) as u32;

        //make sure that the message length is a multiple of 64 bytes
        assert!(
            msg_len % 64 == 0,
            "Message length must be a multiple of 64 bytes"
        );

        let mut stack = StackTracker::new();

        // generate array of u32 from the input string
        let nu32_arr: Vec<u32> = input_hex_str
            .as_bytes()
            .chunks(8)
            .map(|chunk| {
                // Convert chunk to &str
                let chunk_str = std::str::from_utf8(chunk).unwrap();
                // Parse as u32
                u32::from_str_radix(chunk_str, 16).unwrap()
            })
            .collect();

        //processing the string to corrrect for endianess when pushing into stack
        let input_str_processed = hex::encode(
            nu32_arr
                .iter()
                .flat_map(|i| (i).to_le_bytes())
                .collect::<Vec<_>>(),
        );

        // compute the hash using the official implementation
        let expected_hex_out = blake3::hash(
            &nu32_arr
                .iter()
                .flat_map(|i| (i).to_be_bytes())
                .collect::<Vec<_>>(),
        )
        .to_string();

        // toggle to print debug info
        let show_debug_info = false;

        if show_debug_info {
            println!("Input Hex String :: {}", input_hex_str);
            println!("Input Hex String processed:: {}", input_str_processed);
            println!("Expected Hash :: {}", expected_hex_out);
        }

        // push the input string as nibbles and pack them
        let num_blocks = msg_len / 64;

        for i in (0..num_blocks).rev() {
            let pos_start = 64 * (2 * i) as usize;
            let pos_mid = 64 * (2 * i + 1) as usize;
            let pos_end = 64 * (2 * i + 2) as usize;

            stack.var(
                9,
                script! {
                    {u4_hex_to_nibbles(&input_str_processed[pos_start..pos_mid])}
                    {U254::pack_limbs::<4>()}
                },
                &format!("msg{}p0", i),
            );

            stack.var(
                9,
                script! {
                    {u4_hex_to_nibbles(&input_str_processed[pos_mid..pos_end])}
                    {U254::pack_limbs::<4>()}
                },
                &format!("msg{}p1", i),
            );
        }

        let start = stack.get_script().len();
        let optimized_start = optimize(stack.get_script().compile()).len();

        blake3_u4_compact(&mut stack, msg_len, false, false);

        let end = stack.get_script().len();
        let optimized_end = optimize(stack.get_script().compile()).len();

        //push the expected hash and verify
        stack.var(
            64,
            script! {
                {u4_hex_to_nibbles(&expected_hex_out.chars().rev().collect::<String>())}
            },
            "expected-hash-rev",
        );

        stack.to_altstack();

        stack.custom(
            script! {
                for _ in 0..64{
                    OP_FROMALTSTACK
                    OP_EQUALVERIFY
                }
            },
            1,
            false,
            0,
            "verify",
        );

        stack.op_true();

        assert!(stack.run().success);

        let optimized = optimize(stack.get_script().compile());
        let scr = { script!().push_script(optimized.clone()) };
        let exec_result = execute_script(scr);

        {
            // toggle to print benchmarks
            let show_benchmarks = false;
            if show_benchmarks {
                println!(
                    "Blake3 Script Size for {} bytes : {} ",
                    msg_len,
                    end - start
                );
                println!(
                    "Blake3 Max Stack Use for {} bytes : {}",
                    msg_len,
                    stack.get_max_stack_size()
                );

                println!(
                    "Blake3 Optimized Script Size for {} bytes : {}",
                    msg_len,
                    optimized_end - optimized_start
                );
                println!(
                    "Blake3 Optimized Max Stack use for {} bytes :: {}\n",
                    msg_len, exec_result.stats.max_nb_stack_items
                );
            }
           
        }
        // assert optimized version too
        assert!(debug_script(optimized).0.result().unwrap().success);
    }

    #[test]
    // test on all ones
    fn test_blake3_compact_allones() {
        test_blake3_compact_giveninputhex("f".repeat(128));
    }

    #[test]
    // test on all zeros
    fn test_blake3_compact_allzeros() {
        test_blake3_compact_giveninputhex("0".repeat(128));
    }

    #[test]
    // test on random inputs of varying lengths
    fn test_blake3_compact_randominputs() {
        //gen random hex string (length in bytes)
        fn gen_random_hex_strs(len_bytes: u32) -> String {
            let mut rng = rand::thread_rng();
            (0..(len_bytes * 2))
                .map(|_| format!("{:x}", rng.gen_range(0..16))) // Generate a random hex digit
                .collect()
        }

        test_blake3_compact_giveninputhex(gen_random_hex_strs(64));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(128));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(192));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(256));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 5));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 6));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 7));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 8));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 9));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 10));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 11));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 12));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 13));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 14));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 15));
        test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * 16)); //max size for a chunk 1024 bytes
    }
}
