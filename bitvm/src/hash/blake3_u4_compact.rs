use std::collections::HashMap;

use bitcoin_script_stack::stack::StackTracker;

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;

use hex::FromHex;
use crate::bigint::U256;

use crate::hash::blake3_u4::{compress, get_flags_for_block, TablesVars};

// This implementation assumes you have the input is in compact form on the stack.
// The message must be packed into U256 (which uses 9 limbs 29 bits each) such that it expands a multiple of 128 nibbles
// The padding added by user is removed and 0 is added as padding to prevent maliciously or mistaken wrong padding

/// Compact BLAKE3 hash implementation
///
/// This function computes a BLAKE3 hash where the input is given as U256 such that each msgblock of 64 byte is comprised of 2 U256
/// only expanding each msg block into its nibble form when needed to achieve higher stack efficiency and support for
/// larger message size
/// 
/// ## Parameters:
/// - msg_len: Length of the message. (excluding the padding)
/// - define_var: Set to false if the input on stack is already defined as StackTracker varibles.
/// - use_full_tables: toggle if you want to use full precomputation table or only half tables. Full table is script efficient but uses more stack.
///
/// ## Assumptions:
/// - The stack contains only message. Anything other has to be moved to alt stack. If hashing the empty message of length 0, the stack is empty.
/// - The input message is in compact form as U256 where each message block is comprised of two U256 totalling 18 limbs of 29 bits each. 
/// - The input message must unpack to a multiple of 128 nibbles.
/// - The start of the message is at the top of the stack in the following form:
///        
///  > msgblockn_part0 :U256
///  > msgblockn_part1 :U256
///  > ...
///  > ...
///  > msgblock0_part0 :U256
///  > msgblock0_part1 :U256 (Top of Stack)
///         
/// - The user must ensure padding for the message to align to multiple of (2 * 9) limbs,
///   resulting in a size that expands to a multiple of 128 nibbles. Any incorrectly added
///   padding will be corrected to comply with padding requirement of blake3.
///
/// ## Behavior:
/// 1. Defines stack variables for compact message blocks if `define_var` is enabled.
/// 2. Moves the compact message to an alternate stack for processing.
/// 3. Initializes hash computation tables.
/// 4. Processes each message block:
///     - Unpacks compact message forms.
///     - Corrects any user-provided padding if it is the last block.
///     - Computes the hash for the block using `compress` while maintaining intermediate states.
/// 5. Drops intermediate states and finalizes the hash result on the stack.
///
/// ## Stack Effects:
/// - Temporarily uses the alternate stack for intermediate results and hash computation tables.
/// - Final result is left on the main stack as a BLAKE3 hash value.
///
/// ## Panics:
/// - If `msg_len` is greater than 1024 bytes, the function panics with an assertion error.
/// - If the input is not a multiple of 18 limbs, or doesn't unpack to a multiple of 128 nibbles.
/// - If the stack contains elements other than the message.

pub fn blake3_u4_compact(
    stack: &mut StackTracker,
    mut msg_len: u32,
    define_var: bool,
    use_full_tables: bool,
) {

    // this assumes that the stack is empty
    if msg_len == 0{
        // af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        //hardcoded hash of empty msg
        let empty_msg_hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let empty_msg_hash_bytearray =  <[u8;32]>::from_hex(empty_msg_hash).unwrap();

        stack.custom(script!(
            // push the hash value
            for byte in empty_msg_hash_bytearray{
                {byte}
            }
            //convert bytes to nibbles
            {U256::transform_limbsize(8,4)}
        ), 
        0,
        false,
        0,
        "push empty string hash in nibble form"
        );
        stack.define(8 as u32 * 8, "blake3-hash");
        return;
    }


    // We require message take atmost a chunk. i.e, 1024 bytes.
    assert!(
        msg_len <= 1024,
        "msg length must be less than or equal to 1024 bytes"
    );

    //number of msg blocks
    let num_blocks = f64::ceil(msg_len as f64 / 64 as f64) as u32;

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
                {U256::transform_limbsize(29, 4)}
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
                {U256::transform_limbsize(29,4)}
                for _ in 0..64{
                    OP_FROMALTSTACK
                }
            ),
            1,
            false,
            0,
            &format!("unpack msg{}p0", i),
        );

        // handle padding if it is the last block
        if i == (num_blocks - 1) && msg_len != 64 {
            // due to LE representation, msg portion can be on top of padding.
            let j = msg_len % 4;
            let pad_bytes = 64 + j - msg_len - 4;

            stack.custom(
                script!(
                    //Drop whatever padding has been added for packing to limbs and pad with zeros
                    for _ in 0..(pad_bytes*2){
                        OP_DROP
                    }

                    for _ in 0..(j*2){
                        OP_TOALTSTACK
                    }

                    for _ in 0..(4-j) * 2{
                        OP_DROP
                    }

                    for _ in 0..(4-j) * 2{
                        OP_0
                    }

                    for _ in 0..(j*2){
                        OP_FROMALTSTACK
                    }

                    for _ in 0..(pad_bytes*2){
                        OP_0
                    }
                ),
                0,
                false,
                0,
                "padding",
            );
        }

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
            msg_len.min(64),
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

        if msg_len > 64 {
            msg_len -= 64;
        }
    }
    // drop tables
    tables.drop(stack);

    // get the result hash
    stack.from_altstack_joined(8 as u32 * 8, "blake3-hash");
}

#[cfg(any(feature = "fuzzing", test))]
//verifies that the hash of the input byte slice matches with official implementation.
pub fn test_blake3_compact_givenbyteslice(input_bytes: &[u8], use_full_tables: bool) -> String{

    use crate::execute_script;

    let mut stack = StackTracker::new();
    let msg_len = input_bytes.len();
    
    //compute the official hash
    let expected_hash = blake3::hash(input_bytes);

    //determine amount of padding needed to get the compact working
    let padding_bytes_needed = if msg_len % 64 == 0 {0} else {64 - (msg_len % 64)};
    let mut padded_msg = input_bytes.to_vec();
    padded_msg.extend(std::iter::repeat(0u8).take(padding_bytes_needed));

    assert!(padded_msg.len() % 64 == 0, "padding failed");

       // reverse the 4 byte chunks
    for chunk in padded_msg.chunks_mut(4) {
        chunk.reverse();
    }
 
    // push the msg into the stack and compact it
    stack.custom(script!(
        for chunk in padded_msg.chunks(64).rev(){
            for (i,byte) in chunk.iter().enumerate(){
                {*byte}
                if i == 31 || i == 63{
                    {U256::transform_limbsize(8,29)}
                }
            }
        } 
    ),
    0,
    false,
    0,
    "push_msgs"
    );

    blake3_u4_compact(&mut stack, msg_len as u32, true, use_full_tables);

    //change the hash representation from nibbles to bytes and compare with expected hash value
    stack.custom(script!(
        for (i, byte) in expected_hash.as_bytes().iter().enumerate(){
            {*byte}
            if i % 32 == 31{
                {U256::transform_limbsize(8,4)}
            }
        }
        
        for i in (2..65).rev(){
            {i}
            OP_ROLL
            OP_EQUALVERIFY
        }
        OP_EQUAL
    ),
    0,
    false,
    0,
    "verify");

    assert!(execute_script(stack.get_script()).success);

    expected_hash.to_string()
}
#[cfg(test)]
mod tests {
    pub use bitcoin_script::script;
    use bitcoin_script_stack::{debugger::debug_script, optimizer::optimize, stack::StackTracker};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use super::*;
    use crate::{execute_script, u4::u4_std::u4_hex_to_nibbles};

    fn add_padding(input: String) -> String {
        let len_bytes = input.len() / 2;
        let mut res = String::from(input);

        if len_bytes % 64 != 0 {
            res.push_str(&"1".repeat((64 - (len_bytes % 64)) * 2)); //zero should be added as padding but this is done intentionally to test if blake3_u4_compact can handle wrong padding
        }
        res
    }

    fn gen_random_hex_strs(len_bytes: u32) -> String {
        let mut rng = rand::thread_rng();
        (0..(len_bytes * 2))
            .map(|_| format!("{:x}", rng.gen_range(0..16))) // Generate a random hex digit
            .collect()
    }

    // verifies that the hash of the input hex matches with the official implementation.
    fn test_blake3_compact_giveninputhex(input_hex_str: String, msg_len: u32, use_full_tables: bool) -> String {
        let mut stack = StackTracker::new();

        // convert the input into byte array (LE notation)
        let bytes = hex::decode(input_hex_str.clone()).unwrap();
        let mut input_byte_arr = Vec::with_capacity(bytes.len());
        for chunk in bytes.chunks_exact(4) {
            // Convert chunk to [u8; 4]
            let mut array: [u8; 4] = chunk.try_into().unwrap();
            // Reverse the bytes so they represent a little-endian u32
            array.reverse();
            // Append these reversed bytes to our output
            input_byte_arr.extend_from_slice(&array);
        }

        //processing the string to corrrect for endianess when pushing into stack
        let input_str_processed = hex::encode(input_byte_arr.clone());

        // compute the hash using the official implementation
        let expected_hex_out = blake3::hash(&bytes[0..msg_len as usize]).to_string();

        // toggle to print debug info
        let show_debug_info = false;

        if show_debug_info {
            println!("Input Hex String :: {}", input_hex_str);
            println!("Expected Hash :: {}", expected_hex_out);
        }

        // push the input string as nibbles and pack them
        let num_blocks = input_hex_str.len() / 128;

        for i in (0..num_blocks).rev() {
            let pos_start = 64 * (2 * i) as usize;
            let pos_mid = 64 * (2 * i + 1) as usize;
            let pos_end = 64 * (2 * i + 2) as usize;

            stack.var(
                9,
                script! {
                    {u4_hex_to_nibbles(&input_str_processed[pos_start..pos_mid])}
                    {U256::transform_limbsize(4, 29)}
                },
                &format!("msg{}p0", i),
            );

            stack.var(
                9,
                script! {
                    {u4_hex_to_nibbles(&input_str_processed[pos_mid..pos_end])}
                    {U256::transform_limbsize(4, 29)}
                },
                &format!("msg{}p1", i),
            );
        }

        let start = stack.get_script().len();
        let optimized_start = optimize(stack.get_script().compile()).len();

        blake3_u4_compact(&mut stack, msg_len, false, use_full_tables);

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
        
        // assert optimized version too
        assert!(debug_script(optimized).0.result().unwrap().success);

        expected_hex_out
    }

    // test on all ones
    #[test]
    fn test_blake3_compact_allones() {

        // test with full tables
        test_blake3_compact_giveninputhex("f".repeat(128), 64,true);
        test_blake3_compact_givenbyteslice(&[0b11111111;64], true);

        //test with half tables
        test_blake3_compact_giveninputhex("f".repeat(128), 64, false);
        test_blake3_compact_givenbyteslice(&[0b11111111;64], false); 
    }

    // test on all zeros
    #[test]
    fn test_blake3_compact_allzeros() {

        // test with full tables
        test_blake3_compact_giveninputhex("0".repeat(128), 64, true);
        test_blake3_compact_givenbyteslice(&[0u8;64],true);

        // test with half tables
        test_blake3_compact_giveninputhex("0".repeat(128), 64, false);
        test_blake3_compact_givenbyteslice(&[0u8;64],false);
    }

    // test on random inputs of length that are multiple of 64 bytes
    #[test]
    fn test_blake3_compact_randominputs_multipleof64bytes() {
        for i in 1..=16{
            //test with full table
            test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * i), 64 * i, true);

            //test with half table
            test_blake3_compact_giveninputhex(gen_random_hex_strs(64 * i), 64 * i, false);
        }
    }

    // test on random inputs of random lengths
    #[test]
    fn test_blake3_compact_randominputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10{
            let random_size = rng.gen_range(0..=1024);
            let mut random_byte_slice: Vec<u8> = Vec::with_capacity(random_size);
            
            // Fill the vector with random bytes
            for _ in 0..random_size {
                random_byte_slice.push(rng.gen());
            }

            // test with full tables
            test_blake3_compact_giveninputhex(add_padding(gen_random_hex_strs(random_size as u32)), random_size as u32, true);
            test_blake3_compact_givenbyteslice(&random_byte_slice, true);
        
            // test with half tables
            test_blake3_compact_giveninputhex(add_padding(gen_random_hex_strs(random_size as u32)), random_size as u32, false);
            test_blake3_compact_givenbyteslice(&random_byte_slice, false);
        }
    }

    // test against official test vectors
    #[test]
    fn test_blake3_compact_official_testvectors() {
        use serde::Deserialize;
        use std::error::Error;
        use std::fs::File;
        use std::io::BufReader;

        #[derive(Debug, Deserialize)]
        struct TestVectors {
            cases: Vec<TestCase>,
        }

        #[derive(Debug, Deserialize)]
        struct TestCase {
            input_len: usize,
            hash: String,
        }

        fn read_test_vectors(path: &str) -> Result<TestVectors, Box<dyn Error>> {
            // Open the JSON file
            let file = File::open(path)?;
            let reader = BufReader::new(file);

            // Deserialize the JSON into TestVectors struct
            let test_vectors = serde_json::from_reader(reader)?;

            Ok(test_vectors)
        }

        fn gen_inputs_with_padding(len: usize) -> String {
            // Generate the byte sequence with a repeating pattern of 251 bytes
            let mut bytes: Vec<u8> = (0..251u8).cycle().take(len).collect();
            // Add padding to ensure length is a multple of 64
            if len % 64 != 0 {
                for _ in 0..(64 - (len % 64)) {
                    bytes.push(1); //zero should be added as padding but this is done intentionally to test if blake3_u4_compact can handle incorrect padding
                }
            }
            // Convert each byte to its two-digit hexadecimal representation and concatenate
            bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
        }

        // The official test vectors for blake3 given at https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
        let path = "src/hash/blake3_official_test_vectors.json";

        let test_vectors = read_test_vectors(path).unwrap();

        for (_, case) in test_vectors.cases.iter().enumerate() {
            if case.input_len > 64 && case.input_len <= 65 {
                // testing with the hex form
                assert_eq!(
                    case.hash[0..64],
                    test_blake3_compact_giveninputhex(
                        gen_inputs_with_padding(case.input_len),
                        case.input_len as u32,
                        true //use full tables
                    )
                );
                assert_eq!(
                    case.hash[0..64],
                    test_blake3_compact_giveninputhex(
                        gen_inputs_with_padding(case.input_len),
                        case.input_len as u32,
                        false //use half tables
                    )
                );

                //testing with the byte slice with both full and half table
                let bytes: Vec<u8> = (0..251u8).cycle().take(case.input_len).collect();
                assert_eq!(case.hash[0..64],test_blake3_compact_givenbyteslice(&bytes, true));
                assert_eq!(case.hash[0..64],test_blake3_compact_givenbyteslice(&bytes, false));
            }
        }
    }

    // test zero length input
    #[test]
    fn test_blake3_compact_zerolength_input() {
        // test with full tables
        test_blake3_compact_giveninputhex(String::from(""), 0, true);
        test_blake3_compact_givenbyteslice(&[], true);

        // test with half tables
        test_blake3_compact_giveninputhex(String::from(""), 0, false);
        test_blake3_compact_givenbyteslice(&[], false);
    }

    // should panic when msg len is larger than 1024
    #[test]
    #[should_panic(expected = "msg length must be less than or equal to 1024 bytes")]
    fn test_blake3_compact_large_length() {
        // test with full tables
        test_blake3_compact_giveninputhex(String::from("0".repeat(1025 * 2)), 1025, true);
        test_blake3_compact_givenbyteslice(&[0u8; 1025], true);
        
        // test with half tables
        test_blake3_compact_giveninputhex(String::from("0".repeat(1025 * 2)), 1025, false);
        test_blake3_compact_givenbyteslice(&[0u8; 1025], false);
    }

    // test on single byte 
    #[test]
    fn test_blake3_compact_byte(){
        // test with full tables
        test_blake3_compact_giveninputhex(add_padding(String::from("0a")), 1, true);
        test_blake3_compact_givenbyteslice(&[0b00001010;1], true);

        // test with half tables
        test_blake3_compact_giveninputhex(add_padding(String::from("0a")), 1, false);
        test_blake3_compact_givenbyteslice(&[0b00001010;1], false);
    }
}
