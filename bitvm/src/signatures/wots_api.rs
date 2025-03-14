use crate::signatures::{
    utils::u32_to_le_bytes_minimal,
    winternitz,
    winternitz_hash::{WINTERNITZ_MESSAGE_COMPACT_VERIFIER, WINTERNITZ_MESSAGE_VERIFIER},
};
use crate::treepp::Script;
use bitcoin::Witness;
use paste::paste;

/// Trait for converting a signature into a Script.
pub trait SignatureImpl {
    fn to_script(self) -> Script;
    fn to_compact_script(self) -> Script;
}

/// Macro that implements the WOTS module for a given message length (in bytes).
/// For example:
/// - For 160-bit WOTS, use 20 bytes.
/// - For 256-bit WOTS, use 32 bytes.
macro_rules! impl_wots {
    ($mod_name:ident, $MSG_LEN:expr) => {
        paste! {
            pub mod $mod_name {
                use super::*;
                use bitcoin_script::script;

                /// Message length in bytes.
                pub const MSG_LEN: u32 = $MSG_LEN;
                /// Necessary parameters for the algorithm
                pub const PS: winternitz::Parameters = winternitz::Parameters::new_by_bit_length(MSG_LEN * 8, 4);
                /// Total number of "digits" in the signature.
                pub const N_DIGITS: u32 = PS.total_length();

                /// Public key is an array of 20-byte arrays.
                pub type PublicKey = [[u8; 20]; N_DIGITS as usize];
                /// Signature consists of pairs: (20-byte preimage, 1-byte digit).
                pub type Signature = [([u8; 20], u8); N_DIGITS as usize];

                impl SignatureImpl for Signature {
                    fn to_script(self) -> Script {
                        script! {
                            for (preimage, digit) in self {
                                { preimage.to_vec() }
                                { digit }
                            }
                        }
                    }

                    fn to_compact_script(self) -> Script {
                        script! {
                            for (preimage, _) in self {
                                { preimage.to_vec() }
                            }
                        }
                    }
                }

                /// Create a verification script for a WOTS public key.
                pub fn checksig_verify(public_key: PublicKey) -> Script {
                    WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&PS, &public_key.to_vec())
                }

                /// Changes the format of the signature, from bitcoin witness to array
                pub fn raw_witness_to_signature(sigs: &Witness) -> Signature {
                    // Iterate over the signature pieces two at a time.
                    let mut sigs_vec: Vec<([u8; 20], u8)> = Vec::new();
                    for i in (0..sigs.len()).step_by(2) {
                        let preimage: [u8; 20] = if sigs[i].len() == 0 {
                            [0; 20]
                        } else {
                            sigs[i].try_into().unwrap()
                        };
                        let digit_arr: [u8; 1] = if sigs[i + 1].len() == 0 {
                            [0]
                        } else {
                            sigs[i + 1].try_into().unwrap()
                        };
                        sigs_vec.push((preimage, digit_arr[0]));
                    }
                    sigs_vec.try_into().unwrap()
                }

                /// Changes the format of the signature, from array to bitcoin witness
                pub fn signature_to_raw_witness(sigs: &Signature) -> Witness {
                    let mut w = Witness::new();
                    for (h, digit) in sigs.iter() {
                        w.push(h.to_vec());
                        w.push(u32_to_le_bytes_minimal(*digit as u32));
                    }
                    w
                }

                /// Generate a signature for a message using the provided secret.
                pub fn get_signature(secret: &str, msg_bytes: &[u8]) -> Signature {
                    let secret_key = match hex::decode(secret) {
                        Ok(bytes) => bytes,
                        Err(_) => panic!("Invalid hex string for secret"),
                    };

                    let sigs = WINTERNITZ_MESSAGE_VERIFIER.sign(
                        &PS,
                        &secret_key,
                        &msg_bytes.to_vec(),
                    );
                    assert_eq!(sigs.len(), 2 * N_DIGITS as usize);
                    raw_witness_to_signature(&sigs)
                }

                /// Generate a WOTS public key using the provided secret.
                pub fn generate_public_key(secret: &str) -> PublicKey {
                    let secret_key = match hex::decode(secret) {
                        Ok(bytes) => bytes,
                        Err(_) => panic!("Invalid hex string for secret"),
                    };
                    let pubkey_vec = winternitz::generate_public_key(&PS, &secret_key);
                    pubkey_vec.try_into().unwrap()
                }

                /// A sub-module for the compact signature variant.
                pub mod compact {
                    use super::*;

                    /// The compact signature is just the 20-byte preimages.
                    pub type Signature = [[u8; 20]; N_DIGITS as usize];

                    /// Create a verification script for the compact WOTS public key.
                    pub fn checksig_verify(public_key: PublicKey) -> Script {
                        WINTERNITZ_MESSAGE_COMPACT_VERIFIER.checksig_verify(&PS, &public_key.to_vec())
                    }

                    /// Changes the format of the signature, from bitcoin witness to array
                    pub fn raw_witness_to_signature(sigs: &Witness) -> Signature {
                        // Iterate over the signature pieces two at a time.
                        let mut sigs_vec: Vec<[u8; 20]> = Vec::new();
                        // Iterate over the signature pieces using step_by.
                        for i in 0..sigs.len() {
                            let preimage: [u8; 20] = if sigs[i].len() == 0 {
                                [0; 20]
                            } else {
                                sigs[i].try_into().unwrap()
                            };
                            sigs_vec.push(preimage);
                        }
                        sigs_vec.try_into().unwrap()
                    }

                    /// Changes the format of the signature, from array to bitcoin witness
                    pub fn signature_to_raw_witness(sigs: &Signature) -> Witness {
                        let mut w = Witness::new();
                        for h in sigs.iter() {
                            w.push(h.to_vec());
                        }
                        w
                    }

                    /// Generate a compact signature for a message.
                    pub fn get_signature(secret: &str, msg_bytes: &[u8]) -> Signature {
                        let secret_key = match hex::decode(secret) {
                            Ok(bytes) => bytes,
                            Err(_) => panic!("Invalid hex string for secret"),
                        };

                        let sigs = WINTERNITZ_MESSAGE_COMPACT_VERIFIER.sign(
                            &PS,
                            &secret_key,
                            &msg_bytes.to_vec(),
                        );
                        assert_eq!(sigs.len(), N_DIGITS as usize);
                        raw_witness_to_signature(&sigs)
                    }
                }
            }
        }
    };
}
const BIGINT_LEN: u32 = 32;
pub const HASH_LEN: u32 = 16; // bytes, can lower it to value like 16 or 13 lesser acceptable security

// Expand the macro for the two variants.
impl_wots!(wots_hash, HASH_LEN);
impl_wots!(wots256, BIGINT_LEN);
impl_wots!(wots160, 20);
