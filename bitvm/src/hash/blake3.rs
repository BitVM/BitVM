use std::collections::HashMap;

use bitcoin::hex::FromHex;
use bitcoin_script_stack::stack::StackTracker;
use itertools::Itertools;

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;

use crate::bigint::U256;
use crate::hash::blake3_utils::{compress, get_flags_for_block, TablesVars};

/// Internal BLAKE3 implementation.
///
/// Set `define_var` to `false` if the message on the stack is already defined as [`StackTracker`] variables.
///
/// Set `use_full_tables` to `false` to use half tables instead of full tables.
///
/// ## See
///
/// [`blake3_compute_script_with_limb`].
fn blake3(
    stack: &mut StackTracker,
    mut msg_len: u32,
    define_var: bool,
    use_full_tables: bool,
    limb_len: u8,
) {
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
    assert!(
        (4..32).contains(&limb_len),
        "limb length must be in the range [4, 32)"
    );

    //number of msg blocks
    let num_blocks = msg_len.div_ceil(64);

    // If the compact form of message is on stack but not associated with variable, convert it to StackVariable
    if define_var {
        let limb_count = 256u32.div_ceil(limb_len as u32);
        for i in (0..num_blocks).rev() {
            stack.define(limb_count, &format!("msg{}p0", i));
            stack.define(limb_count, &format!("msg{}p1", i));
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
                {U256::transform_limbsize(limb_len as u32, 4)}
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
                {U256::transform_limbsize(limb_len as u32, 4)}
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
                    for _ in 0..pad_bytes {
                        OP_2DROP
                    }

                    for _ in 0..(j*2) {
                        OP_TOALTSTACK
                    }

                    for _ in 0..(4-j) {
                        OP_2DROP
                    }

                    for j in 0..(4-j) * 2 {
                        if j <= 1 {
                            OP_0
                        } else if j % 2 == 1 {
                            OP_2DUP
                        } // no else since loop is even
                    }

                    for _ in 0..(j*2){
                        OP_FROMALTSTACK
                    }

                    for j in 0..(pad_bytes*2) {
                        if j <= 1 {
                            OP_0
                        } else if j % 2 == 1 {
                            OP_2DUP
                        } // no else since loop is even
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
pub fn blake3_push_message_script(message_bytes: &[u8], limb_len: u8) -> Script {
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
                        U256::transform_limbsize(8, limb_len as u32)
                    }
                }
            }
        }
    }
}

/// Number of elements in total of all tables
const SUM_OF_FULL_TABLES: usize = 384;

/// Number of elements of an unpacked block
const UNPACKED_BLOCK: usize = 128;

/// Maximum number of elements in stack during the execution of BLAKE3 algorithm
const MAX_BLAKE3_ELEMENT_COUNT: usize =
    SUM_OF_FULL_TABLES + UNPACKED_BLOCK + /* Extra BLAKE3 variables */ 132;

/// Calculates the maximum number of altstack elements one can have using the [`blake3_compute_script`] function with the following formula:
/// ```text
///  n (number of blocks) = ⌈msg_len / 64⌉
///  limb_count (number of limbs in a block) = ⌈256 / limb_len⌉ * 2
///  m (message's consumption of stack during BLAKE3) = (n - 1) * limb_count
///  Since BLAKE3 requires an empty stack and we've calculated the usage for the message and the algorithm:
///  MAX_NUMBEROF_ALTSTACK_ELEMENTS = 1000 (max stack limit) - m - 644 (Maximum number of elements used during BLAKE3)
/// ```
pub fn maximum_number_of_altstack_elements_using_blake3(message_len: usize, limb_len: u8) -> i32 {
    let n = message_len.div_ceil(64);
    let limb_count = 256usize.div_ceil(limb_len as usize) * 2;
    let m = (n - 1) * limb_count;
    let max_altstack_elements = 1000i32 - MAX_BLAKE3_ELEMENT_COUNT as i32 - m as i32;
    max_altstack_elements
}

/// Returns a script that computes the BLAKE3 hash of the message on the stack.
///
/// The script processes compact message blocks and only unpacks them when needed,
/// resulting in higher stack efficiency and support for larger messages.
///
/// ## Parameters:
///
/// - `msg_len`: Length of the message. (excluding the padding, number of bytes)
/// - `define_var`: Set to false if the input on stack is already defined as `StackTracker` varibles.
/// - `use_full_tables`: toggle if you want to use full precomputation table or only half tables. Full table is script efficient but uses more stack.
/// - `limb_len`: Limb length (number of bits per element) that the input in the stack is packed, for example it is 29 for current field elements
///
/// ## Message Format Requirements:
///
/// - __The stack contains only message. Anything other has to be moved to alt stack.__ If hashing the empty message of length 0, the stack is empty.
/// - The input message is in the form U256 where each message block is comprised of two U256, each represented with elements consisting of `limb_len` bits
/// - The input message must unpack to a multiple of 128 nibbles, so pushing padding bytes is necessary
/// - __BLAKE3 uses exactly [`MAX_BLAKE3_ELEMENT_COUNT`] = 644 elements at maximum, including the tables__ \
///  With the max stack limit 1000, __you are allowed to have at most 356 elements including the message (excluding the first block of it) in stack (in total, of altstack and stack)__ \
///  Note that smaller `limb_len`'s means more elements, hence more stack usage \
///  For a more certain number, you can look into and use [`maximum_number_of_altstack_elements_using_blake3`]
/// - A message of `n` blocks is expected in the following format:
///
/// ```text
/// block_n_part_0 : U256
/// block_n_part_1 : U256
/// ...
/// block_0_part_0 : U256
/// block_0_part_1 : U256 (top of the stack)
/// ```
/// ## Panics:
///
/// - If `msg_len` is greater than 1024 bytes, the function panics with an assertion error.
/// - Given script might not also fit on the max stack limit with messages smaller than 1024 bytes \
///   if the `limb_len` is small or input stacks has other elements (in the altstack)
/// - If `limb_len` is not in the range [4, 32)
/// - If the input doesn't unpack to a multiple of 128 nibbles with the given limb length parameter.
/// - If the stack contains elements other than the message.
///
/// ## Implementation:
///
/// 1. Defines stack variables for compact message blocks if `define_var` is enabled.
/// 2. Moves the compact message to an alternate stack for processing.
/// 3. Initializes hash computation tables.
/// 4. Processes each message block:
///     - Unpacks message block.
///     - Corrects any user-provided padding if it is the last block.
///     - Computes the hash for the block using `compress` while maintaining intermediate states.
/// 5. Drops intermediate states and finalizes the hash result on the stack.
///
/// ## Stack Effects:
///
/// - Temporarily uses the alternate stack for intermediate results and hash computation tables.
/// - Final result is left on the main stack as a BLAKE3 hash value. (in nibbles)
///
pub fn blake3_compute_script_with_limb(message_len: usize, limb_len: u8) -> Script {
    assert!(
        message_len <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    let mut stack = StackTracker::new();
    let use_full_tables = true;
    let message_len = message_len as u32; // safety: message_len <= 1024 << u32::MAX
    blake3(&mut stack, message_len, true, use_full_tables, limb_len);
    stack.get_script()
}

/// Uses [`blake3_compute_script_with_limb`].with limb length 29, see the documentation of it for more details
pub fn blake3_compute_script(message_len: usize) -> Script {
    blake3_compute_script_with_limb(message_len, 29)
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
    use crate::{execute_script, execute_script_buf_without_stack_limit};
    use bitcoin::ScriptBuf;
    use bitcoin_script_stack::optimizer;

    /// Since testing all possible limb lengths takes relatively long time, only limb lengths that are useful are tested in default
    /// If any changes are done to the code, running the extensive tests with all possible lengths is a good idea
    const RUN_EXTENSIVE_TESTS: bool = false;

    const ALL_POSSIBLE_LIMB_LENGTHS: [u8; 28] = [
        4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 31,
    ];

    const USEFUL_LIMB_LENGTHS: [u8; 2] = [4, 29];

    const TESTED_LIMB_LENGTHS: &[u8] = match RUN_EXTENSIVE_TESTS {
        true => &ALL_POSSIBLE_LIMB_LENGTHS,
        false => &USEFUL_LIMB_LENGTHS,
    };

    fn test_blake3_stack_space(
        blake3_script: Script,
        message_len: usize,
        limb_len: u8,
        extra_elements: i32,
    ) -> bool {
        let message = vec![0u8; message_len];
        execute_script(script! {
            for _ in 0..extra_elements {
                { -1 } OP_TOALTSTACK
            }
            { blake3_push_message_script(&message, limb_len) }
            { blake3_script.clone() }
            for _ in 0..extra_elements {
                OP_FROMALTSTACK OP_DROP
            }
            for _ in 0..64 {
                OP_DROP
            }
            OP_TRUE
        })
        .success
    }

    #[test]
    pub fn test_maximum_alstack_element_calculation() {
        for limb_len in TESTED_LIMB_LENGTHS.iter().copied() {
            for message_len in (64..=1024).step_by(64) {
                // Block count depends on ceil(message_len / 64)
                let blake3_script = blake3_compute_script_with_limb(message_len, limb_len);
                let maximum_extra_elements =
                    maximum_number_of_altstack_elements_using_blake3(message_len, limb_len);
                if maximum_extra_elements < 0 {
                    assert!(!test_blake3_stack_space(
                        blake3_script.clone(),
                        message_len,
                        limb_len,
                        0
                    ));
                } else {
                    assert!(test_blake3_stack_space(
                        blake3_script.clone(),
                        message_len,
                        limb_len,
                        maximum_extra_elements
                    ));
                    assert!(!test_blake3_stack_space(
                        blake3_script.clone(),
                        message_len,
                        limb_len,
                        maximum_extra_elements + 1
                    ));
                }
            }
        }
    }

    pub fn verify_blake_output(message: &[u8], expected_hash: [u8; 32]) {
        use bitcoin_script_stack::optimizer;
        for limb_len in TESTED_LIMB_LENGTHS.iter().copied() {
            let mut bytes = blake3_push_message_script(&message, limb_len)
                .compile()
                .to_bytes();
            let optimized = optimizer::optimize(
                blake3_compute_script_with_limb(message.len(), limb_len).compile(),
            );
            bytes.extend(optimized.to_bytes());
            bytes.extend(
                blake3_verify_output_script(expected_hash)
                    .compile()
                    .to_bytes(),
            );
            let script = ScriptBuf::from_bytes(bytes);
            assert!(execute_script_buf_without_stack_limit(script).success);
        }
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
        for limb_len in TESTED_LIMB_LENGTHS.iter().copied() {
            let optimized =
                optimizer::optimize(blake3_compute_script_with_limb(LEN, limb_len).compile());
            for (i, message) in messages.iter().enumerate() {
                let expected_hash = expected_hashes[i];
                let mut bytes = blake3_push_message_script(message, limb_len)
                    .compile()
                    .to_bytes();
                bytes.extend_from_slice(optimized.as_bytes());
                bytes.extend(
                    blake3_verify_output_script(expected_hash)
                        .compile()
                        .to_bytes(),
                );
                let script = ScriptBuf::from_bytes(bytes);
                assert!(execute_script_buf_without_stack_limit(script).success);
            }
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
