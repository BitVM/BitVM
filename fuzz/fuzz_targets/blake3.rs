#![no_main]

use std::sync::LazyLock;

use bitcoin::ScriptBuf;
use bitcoin_script_stack::optimizer;
use libfuzzer_sys::fuzz_target;

use bitvm::execute_script_buf;
use bitvm::hash::blake3::{
    blake3_compute_script, blake3_push_message_script, blake3_verify_output_script,
};

static BLAKE3_COMPUTE_SCRIPT: LazyLock<ScriptBuf> =
    LazyLock::new(|| optimizer::optimize(blake3_compute_script(32).compile()));

fuzz_target!(|message: [u8; 32]| {
    let expected_hash = blake3::hash(&message).as_bytes().clone();

    let mut bytes = blake3_push_message_script(&message).compile().to_bytes();
    bytes.extend_from_slice(BLAKE3_COMPUTE_SCRIPT.as_bytes());
    bytes.extend(
        blake3_verify_output_script(expected_hash)
            .compile()
            .to_bytes(),
    );
    let script = ScriptBuf::from_bytes(bytes);
    assert!(execute_script_buf(script).success);
});
