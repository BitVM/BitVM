use std::collections::HashMap;

use bitcoin::hex::FromHex;
use bitcoin_script_stack::stack::StackTracker;
use itertools::Itertools;

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;

use crate::bigint::U256;
use crate::hash::blake3_utils::{compress, get_flags_for_block, TablesVars};

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

pub fn blake3(stack: &mut StackTracker, mut msg_len: u32, define_var: bool, use_full_tables: bool) {
    // this assumes that the stack is empty
    if msg_len == 0 {
        // af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        //hardcoded hash of empty msg
        let empty_msg_hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let empty_msg_hash_bytearray = <[u8; 32]>::from_hex(empty_msg_hash).unwrap();

        stack.custom(
            script!(
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
            "push empty string hash in nibble form",
        );
        stack.define(8_u32 * 8, "blake3-hash");
        return;
    }

    // We require message take atmost a chunk. i.e, 1024 bytes.
    assert!(
        msg_len <= 1024,
        "msg length must be less than or equal to 1024 bytes"
    );

    //number of msg blocks
    let num_blocks = f64::ceil(msg_len as f64 / 64_f64) as u32;

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
    stack.from_altstack_joined(8_u32 * 8, "blake3-hash");
}

/// Transforms the given message into a format that BLAKE3 understands.
fn chunk_message(message_bytes: &[u8]) -> Vec<[u8; 64]> {
    let len = message_bytes.len();
    let needed_padding_bytes = if len % 64 == 0 { 0 } else { 64 - (len % 64) };

    message_bytes
        .iter()
        .copied()
        .chain(std::iter::repeat(0u8).take(needed_padding_bytes))
        .chunks(4) // reverse 4-byte chunks
        .into_iter()
        .flat_map(|chunk| chunk.collect::<Vec<u8>>().into_iter().rev())
        .chunks(64) // collect 64-byte chunks
        .into_iter()
        .map(|mut chunk| std::array::from_fn(|_| chunk.next().unwrap()))
        .collect()
}

/// Returns a script that pushes the given message onto the stack for BLAKE3.
///
/// The script transforms the message into the correct format
/// and pushes the result onto the stack.
///
/// ## Panics
///
/// This function panics if the message is longer than 1024 bytes,
/// since our BLAKE3 implementation doesn't support longer messages.
pub fn blake3_push_message_script(message_bytes: &[u8]) -> Script {
    assert!(
        message_bytes.len() <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    let chunks = chunk_message(message_bytes);

    script! {
        for chunk in chunks.into_iter().rev() {
            for (i, byte) in chunk.into_iter().enumerate() {
                {
                    byte
                }
                if i == 31 || i == 63 {
                    {
                        U256::transform_limbsize(8, 29)
                    }
                }
            }
        }
    }
}

/// Returns a script that computes the BLAKE3 hash of the message on the stack.
///
/// ## Panics
///
/// This function panics if the message is longer than 1024 bytes,
/// since our BLAKE3 implementation doesn't support longer messages.
pub fn blake3_compute_script(message_len: usize) -> Script {
    assert!(
        message_len <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    let mut stack = StackTracker::new();
    let use_full_tables = true;
    blake3(&mut stack, message_len as u32, true, use_full_tables);
    stack.get_script()
}

/// Returns a script that verifies the BLAKE3 output on the stack.
///
/// The script pops the BLAKE3 output and compares it with the given, expected output.
pub fn blake3_verify_output_script(expected_output: [u8; 32]) -> Script {
    script! {
        for (i, byte) in expected_output.into_iter().enumerate() {
            {byte}
            if i % 32 == 31 {
                {U256::transform_limbsize(8,4)}
            }
        }

        for i in (2..65).rev() {
            {i}
            OP_ROLL
            OP_EQUALVERIFY
        }
        OP_EQUAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execute_script_buf;
    use bitcoin::ScriptBuf;
    use bitcoin_script_stack::optimizer;

    pub fn verify_blake_output(message: &[u8], expected_hash: [u8; 32]) {
        use crate::execute_script_buf;
        use bitcoin_script_stack::optimizer;

        let mut bytes = blake3_push_message_script(&message).compile().to_bytes();
        let optimized = optimizer::optimize(blake3_compute_script(message.len()).compile());
        bytes.extend(optimized.to_bytes());
        bytes.extend(
            blake3_verify_output_script(expected_hash)
                .compile()
                .to_bytes(),
        );
        let script = ScriptBuf::from_bytes(bytes);
        assert!(execute_script_buf(script).success);
    }

    fn verify_blake_outputs_cached<const LEN: usize>(
        messages: &[[u8; LEN]],
        expected_hashes: &[[u8; 32]],
    ) {
        assert_eq!(
            messages.len(),
            expected_hashes.len(),
            "There must be as many messages as there are expected hashes"
        );
        let optimized = optimizer::optimize(blake3_compute_script(LEN).compile());

        for (i, message) in messages.iter().enumerate() {
            let expected_hash = expected_hashes[i];

            let mut bytes = blake3_push_message_script(message).compile().to_bytes();
            bytes.extend_from_slice(optimized.as_bytes());
            bytes.extend(
                blake3_verify_output_script(expected_hash)
                    .compile()
                    .to_bytes(),
            );
            let script = ScriptBuf::from_bytes(bytes);
            assert!(execute_script_buf(script).success);
        }
    }

    #[test]
    fn test_zero_length() {
        let message = [];
        let expected_hash = blake3::hash(&message).as_bytes().clone();
        verify_blake_output(&message, expected_hash);
    }

    #[test]
    fn test_max_length() {
        let message = [0x00; 1024];
        let expected_hash = blake3::hash(&message).as_bytes().clone();
        verify_blake_output(&message, expected_hash);
    }

    #[test]
    #[should_panic(
        expected = "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    )]
    fn test_too_long() {
        let message = [0x00; 1025];
        let expected_hash = blake3::hash(&message).as_bytes().clone();
        verify_blake_output(&message, expected_hash);
    }

    #[test]
    fn test_single_byte() {
        let messages: Vec<[u8; 1]> = (0..=255).map(|byte| [byte]).collect();
        let expected_hashes: Vec<[u8; 32]> = messages
            .iter()
            .map(|message| blake3::hash(message).as_bytes().clone())
            .collect();
        verify_blake_outputs_cached(&messages, &expected_hashes);
    }

    #[test]
    fn test_official_test_vectors() {
        use serde::Deserialize;
        use std::fs::File;
        use std::io::BufReader;

        #[derive(Debug, Deserialize)]
        struct TestVectors {
            cases: Vec<TestVector>,
        }

        #[derive(Debug, Deserialize)]
        struct TestVector {
            input_len: usize,
            hash: String,
        }

        fn read_test_vectors() -> Vec<(Vec<u8>, [u8; 32])> {
            let path = "src/hash/blake3_official_test_vectors.json";
            let file = File::open(path).unwrap();
            let reader = BufReader::new(file);

            let test_vectors: TestVectors = serde_json::from_reader(reader).unwrap();
            test_vectors
                .cases
                .iter()
                .filter(|vector| vector.input_len <= 1024)
                .map(|vector| {
                    let message = (0..251u8).cycle().take(vector.input_len).collect();
                    let expected_hash = <[u8; 32]>::from_hex(&vector.hash[0..64]).unwrap();
                    (message, expected_hash)
                })
                .collect()
        }

        let test_vectors = read_test_vectors();
        for (message, expected_hash) in test_vectors {
            verify_blake_output(&message, expected_hash);
        }
    }
}
