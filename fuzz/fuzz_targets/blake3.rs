#![no_main]

use std::iter::IntoIterator;
use std::sync::LazyLock;

use arbitrary::Arbitrary;
use bitcoin::ScriptBuf;
use bitcoin_script_stack::optimizer;
use bitvm::execute_script_buf;
use bitvm::hash::blake3::{
    blake3_compute_script, blake3_push_message_script_with_limb, blake3_verify_output_script,
};
use libfuzzer_sys::fuzz_target;

static BLAKE3_COMPUTE_SCRIPTS: LazyLock<[ScriptBuf; 4]> = LazyLock::new(|| {
    [64, 128, 192, 448]
        .into_iter()
        .map(|msg_len| blake3_compute_script(msg_len).compile())
        .map(|script| optimizer::optimize(script))
        .collect::<Vec<ScriptBuf>>()
        .try_into()
        .unwrap()
});

/// Cover all message sizes that are used inside BitVM.
///
/// Each message size is processed by a different BLAKE3 Bitcoin script.
/// Computing and optimizing each of these scripts takes considerable time.
/// Even when we cache the result, the fuzzer has to wait until all scripts are gennerated.
///
/// In order to get useful coverage while keeping computational effort low,
/// we fuzz exactly the message sizes that are used inside BitVM.
/// It turns out, there are only four different sizes.
#[derive(Debug, Clone, Arbitrary)]
enum MessageBytes {
    U64([u8; 64]),
    U128([u8; 128]),
    U192([u8; 192]),
    U448([u8; 448]),
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
    pub fn blake3_compute_script(&self) -> &'static ScriptBuf {
        let index = match self {
            Self::U64(..) => 0,
            Self::U128(..) => 1,
            Self::U192(..) => 2,
            Self::U448(..) => 3,
        };
        &BLAKE3_COMPUTE_SCRIPTS[index]
    }
}

fuzz_target!(|message: MessageBytes| {
    let expected_hash = *blake3::hash(message.as_ref()).as_bytes();
    // Fuzz tests are left only for bigints (limb_len = 29)
    let mut bytes = blake3_push_message_script_with_limb(message.as_ref(), 29)
        .compile()
        .to_bytes();
    bytes.extend_from_slice(message.blake3_compute_script().as_bytes());
    bytes.extend_from_slice(
        blake3_verify_output_script(expected_hash)
            .compile()
            .as_bytes(),
    );
    let script = ScriptBuf::from_bytes(bytes);
    assert!(execute_script_buf(script).success);
});
