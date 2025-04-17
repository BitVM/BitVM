#![no_main]

use std::sync::LazyLock;
use std::array;

use arbitrary::Arbitrary;
use bitcoin::ScriptBuf;
use bitcoin_script_stack::optimizer;
use bitvm::execute_script_buf;
use bitvm::hash::blake3::{
    blake3_compute_script, blake3_push_message_script_with_limb, blake3_verify_output_script,
};
use libfuzzer_sys::fuzz_target;

/// Optimized LazyLock initialization to avoid unnecessary Vec allocation.
static BLAKE3_COMPUTE_SCRIPTS: LazyLock<[ScriptBuf; 4]> = LazyLock::new(|| {
    array::from_fn(|i| optimizer::optimize(blake3_compute_script([64, 128, 192, 448][i]).compile()))
});

/// Cover all message sizes that are used inside BitVM.
///
/// Each message size is processed by a different BLAKE3 Bitcoin script.
/// Computing and optimizing each of these scripts takes considerable time.
/// Even when we cache the result, the fuzzer has to wait until all scripts are generated.
///
/// In order to get useful coverage while keeping computational effort low,
/// we fuzz exactly the message sizes that are used inside BitVM.
/// It turns out, there are only four different sizes.
#[derive(Debug, Clone, Arbitrary)]
#[repr(usize)]  // Ensure the enum can be directly cast to usize
#[allow(clippy::large_enum_variant)]
enum MessageBytes {
    U64([u8; 64]) = 0,
    U128([u8; 128]) = 1,
    U192([u8; 192]) = 2,
    U448([u8; 448]) = 3,
}

impl AsRef<[u8]> for MessageBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::U64(bytes) => bytes,
            Self::U128(bytes) => bytes,
            Self::U192(bytes) => bytes,
            Self::U448(bytes) => bytes,
        }
    }
}

impl MessageBytes {
    /// Optimized to use enum indexing instead of match.
    pub fn blake3_compute_script(&self) -> &'static ScriptBuf {
        &BLAKE3_COMPUTE_SCRIPTS[*self as usize]
    }
}

fuzz_target!(|message: MessageBytes| {
    let expected_hash = *blake3::hash(message.as_ref()).as_bytes();
    // Fuzz tests are left only for bigints (limb_len = 29)
    let mut bytes = blake3_push_message_script_with_limb(message.as_ref(), 29)
        .compile()
        .to_bytes();
    
    // Optimized by reducing multiple extend_from_slice calls
    bytes.extend([
        message.blake3_compute_script().as_bytes(),
        blake3_verify_output_script(expected_hash).compile().as_bytes(),
    ].concat());
    
    let script = ScriptBuf::from_bytes(bytes);
    assert!(execute_script_buf(script).success);
});
