#![no_main]

use std::sync::LazyLock;
use std::iter::IntoIterator;

use arbitrary::Arbitrary;
use bitcoin::ScriptBuf;
use bitcoin_script_stack::optimizer;
use bitvm::execute_script_buf;
use bitvm::hash::sha256::{sha256, sha256_push_message, sha256_verify_output_script};
use sha2::{Digest, Sha256};

use libfuzzer_sys::fuzz_target;

static SHA256_COMPUTE_SCRIPT: LazyLock<[ScriptBuf; 2]> = LazyLock::new(|| {
    [32, 80]
        .into_iter()
        .map(|msg_length| sha256(msg_length).compile())
        .map(optimizer::optimize)
        .collect::<Vec<ScriptBuf>>()
        .try_into()
        .unwrap()
});

#[derive(Debug, Clone, Arbitrary)]
enum MessageBytes {
    U32([u8; 32]),
    U80([u8; 80]),
}

impl AsRef<[u8]> for MessageBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::U32(bytes) => bytes,
            Self::U80(bytes) => bytes,
        }
    }
}

impl MessageBytes {
    pub fn sha256_compute_script(&self) -> &'static ScriptBuf {
        let index = match self {
            Self::U32(_) => 0,
            Self::U80(_) => 1,
        };
        &SHA256_COMPUTE_SCRIPT[index]
    }
}

// Fuzz for double SHA256
fuzz_target!(|message: MessageBytes| {
    let mut hasher = Sha256::new();
    hasher.update(message.as_ref());
    let hash = hasher.finalize();
    hasher = Sha256::new();
    hasher.update(hash);
    let expected_hash: [u8; 32] = hasher.finalize().into();

    let mut bytes = sha256_push_message(message.as_ref()).compile().to_bytes();
    bytes.extend_from_slice(message.sha256_compute_script().as_bytes());
    bytes.extend_from_slice(SHA256_COMPUTE_SCRIPT[0].as_bytes());
    bytes.extend_from_slice(
        sha256_verify_output_script(expected_hash)
            .compile()
            .as_bytes(),
    );
    let script = ScriptBuf::from_bytes(bytes);
    assert!(execute_script_buf(script).success);
});
