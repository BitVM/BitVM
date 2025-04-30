use super::winternitz::*;
use bitcoin::Witness;
use blake3::hash;

const MESSAGE_HASH_LEN: u32 = 20;
/// Winternitz parameters for the 20 byte blake3 variant with the block length 4
pub const WINTERNITZ_HASH_PARAMETERS: Parameters =
    Parameters::new_by_bit_length(MESSAGE_HASH_LEN * 8, 4);

/// Winternitz verifier for the 20 byte blake3 variant (can be used with other parameters), returns the message in bytes
pub const WINTERNITZ_HASH_VERIFIER: Winternitz<ListpickVerifier, ToBytesConverter> =
    Winternitz::new();

/// Winternitz verifier, returns the message in blocks
pub const WINTERNITZ_MESSAGE_VERIFIER: Winternitz<ListpickVerifier, VoidConverter> =
    Winternitz::new();

/// Winternitz verifier, returns the message in in bytes
pub const WINTERNITZ_VARIABLE_VERIFIER: Winternitz<ListpickVerifier, ToBytesConverter> =
    Winternitz::new();

/// Winternitz verifier for compact signature representation, returns the message in in bytes
pub const WINTERNITZ_MESSAGE_COMPACT_VERIFIER: Winternitz<BruteforceVerifier, VoidConverter> =
    Winternitz::new();

/// Create a Winternitz signature for the blake3 hash of a given message
pub fn sign_hash(sec_key: &Vec<u8>, message: &[u8]) -> Witness {
    let message_hash = hash(message);
    let message_hash_bytes = &message_hash.as_bytes()[0..20];
    WINTERNITZ_HASH_VERIFIER.sign(&WINTERNITZ_HASH_PARAMETERS, sec_key, message_hash_bytes)
}
