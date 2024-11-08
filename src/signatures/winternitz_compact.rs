//
// Compact Winternitz Signatures
//
// In this variant, the user doesn't need to provide the message in the unlocking script.
// Instead, we calculate the message from the signature hashes.
// This reduces stack usage at the expense of script size.
//

//
// Winternitz signatures are an improved version of Lamport signatures.
// A detailed introduction to Winternitz signatures can be found
// in "A Graduate Course in Applied Cryptography" in chapter 14.3
// https://toc.cryptobook.us/book.pdf
//
// We are trying to closely follow the authors' notation here.
//

//
// BEAT OUR IMPLEMENTATION AND WIN A CODE GOLF BOUNTY!
//

use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};
use hex::decode as hex_decode;

use super::winternitz::{PublicKey, N};

/// Bits per digit
const LOG_D: u32 = 4;
/// Digits are base d+1
pub const D: u32 = (1 << LOG_D) - 1;

/// For 320 bits - currently only used in tests
/// Number of digits of the message
#[cfg(test)]
const N0_320: usize = 80;
/// Number of digits of the checksum
#[cfg(test)]
const N1_320: usize = 4;
/// Total number of digits to be signed
#[cfg(test)]
const N_320: usize = N0_320 + N1_320;

/// For 32 bits
/// Number of digits of the message
pub const N0_32: usize = 8;
/// Number of digits of the checksum
pub const N1_32: usize = 2;
/// Total number of digits to be signed
pub const N_32: usize = N0_32 + N1_32;

pub const HASH160_LENGTH_IN_BYTES: usize = hash160::Hash::LEN;

/// Contains public keys for all the message and checksum digits.
pub type PublicKeyCompact<const TOTAL_DIGIT_COUNT: usize> =
    [[u8; HASH160_LENGTH_IN_BYTES]; TOTAL_DIGIT_COUNT];

pub fn into_public_key<const TOTAL_DIGIT_COUNT: usize>(
    public_key_compact: &PublicKeyCompact<TOTAL_DIGIT_COUNT>,
) -> Result<PublicKey, String> {
    if public_key_compact.len() != (N as usize) {
        return Err(format!(
            "Invalid public key length: expected {}, but got {}",
            N,
            public_key_compact.len()
        ));
    }

    let mut public_key_array = [[0u8; HASH160_LENGTH_IN_BYTES]; N as usize];
    for i in 0..N {
        public_key_array[i as usize] = public_key_compact[i as usize].try_into().expect(
            format!(
                "A Winternitz public key for a digit must be {HASH160_LENGTH_IN_BYTES} bytes long"
            )
            .as_str(),
        );
    }

    Ok(public_key_array)
}

/// Winternitz Signature verification
///
/// Note that the script inputs are malleable.
///
/// Optimized by @SergioDemianLerner, @tomkosm
pub fn checksig_verify<const TOTAL_DIGIT_COUNT: usize, const DIGIT_COUNT: usize>(
    public_key: &PublicKeyCompact<TOTAL_DIGIT_COUNT>,
) -> Script {
    #[allow(non_snake_case)]
    let CHECKSUM_DIGIT_COUNT: usize = TOTAL_DIGIT_COUNT - DIGIT_COUNT;
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..(DIGIT_COUNT + CHECKSUM_DIGIT_COUNT) {

            { public_key[(DIGIT_COUNT + CHECKSUM_DIGIT_COUNT - 1 - digit_index) as usize].to_vec() }

            // Check if hash is equal with public key and add digit to altstack.
            // We dont check if a digit was found to save space, incase we have an invalid hash
            // there will be one fewer entry in altstack and OP_FROMALTSTACK later will crash.
            // So its important to start with the altstack empty.
            // TODO: add testcase for this.
            OP_SWAP

            OP_2DUP
            OP_EQUAL

            OP_IF

                {D}

                OP_TOALTSTACK

            OP_ENDIF

            for i in 0..D {

                OP_HASH160

                OP_2DUP

                OP_EQUAL

                OP_IF

                    {D-i-1}

                    OP_TOALTSTACK

                OP_ENDIF
            }

            OP_2DROP
        }


        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..DIGIT_COUNT{
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * DIGIT_COUNT as u32 }
        OP_ADD


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..CHECKSUM_DIGIT_COUNT - 1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY


        // No need to convert message digits to bytes.
        // We can get the actual number by calling `message_digits_to_number()`.

        // // Convert the message's digits to bytes
        // for i in 0..DIGIT_COUNT / 2 {
        //     OP_SWAP
        //     for _ in 0..LOG_D {
        //         OP_DUP OP_ADD
        //     }
        //     OP_ADD
        //     // Push all bytes to the altstack, except for the last byte
        //     if i != (DIGIT_COUNT/2) - 1 {
        //         OP_TOALTSTACK
        //     }
        // }
        // for _ in 0..DIGIT_COUNT / 2 - 1 {
        //     OP_FROMALTSTACK
        // }
    }
}

/// Compute the signature for a given message
pub fn sign<const DIGIT_COUNT: usize, const CHECKSUM_DIGIT_COUNT: usize>(
    secret_key: &str,
    message_digits: [u8; DIGIT_COUNT],
) -> Vec<Vec<u8>> {
    let mut checksum_digits =
        checksum_to_digits::<CHECKSUM_DIGIT_COUNT>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    let mut signatures = Vec::new();
    for i in 0..(DIGIT_COUNT + CHECKSUM_DIGIT_COUNT) as u32 {
        signatures.push(digit_signature(
            secret_key,
            i,
            checksum_digits[DIGIT_COUNT + CHECKSUM_DIGIT_COUNT - 1 - i as usize],
        ));
    }

    signatures
}

/// Compute the signature for the i-th digit of the message
fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u8) -> Vec<u8> {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    hash_bytes
}

/// Compute the checksum of the message's digits.
/// Further infos in chapter "A domination free function for Winternitz signatures"
fn checksum<const DIGIT_COUNT: usize>(digits: [u8; DIGIT_COUNT]) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    D * DIGIT_COUNT as u32 - sum
}

/// Convert a number to digits in Little Endian order
pub fn checksum_to_digits<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D + 1);
        number = (number - digit) / (D + 1);
        digits[i] = digit as u8;
    }
    digits
}

/// Convert a number to digits in Big Endian order
pub fn message_to_digits<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D + 1);
        number = (number - digit) / (D + 1);
        digits[DIGIT_COUNT - 1 - i] = digit as u8;
    }
    digits
}

pub fn digits_to_number<const DIGIT_COUNT: usize>() -> Script {
    // Expects digits in order on stack in Little Endian (most significant bytes at top of stack, least significant bytes at bottom of stack)
    script!(
        for _ in 0..DIGIT_COUNT - 1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_ADD
        }
    )
}

pub fn digits_to_bytes<const DIGIT_COUNT: usize>() -> Script {
    // Expects digits in order on stack in Little Endian (most significant bytes at top of stack, least significant bytes at bottom of stack)
    script!(
        // Convert the message's digits to bytes
        for i in 0..DIGIT_COUNT / 2 {
          OP_SWAP
          for _ in 0..LOG_D {
              OP_DUP OP_ADD
          }
          OP_ADD
          // Push all bytes to the altstack, except for the last byte
          if i != (DIGIT_COUNT/2) - 1 {
              OP_TOALTSTACK
          }
        }
        for _ in 0..DIGIT_COUNT / 2 - 1 {
            OP_FROMALTSTACK
        }
    )
}

#[cfg(test)]
mod test {
    use super::*;

    // The secret key
    const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    //
    // Helper functions
    //

    fn public_key<const DIGIT_COUNT: usize>(secret_key: &str) -> PublicKeyCompact<DIGIT_COUNT> {
        let mut public_key_array = [[0u8; HASH160_LENGTH_IN_BYTES]; DIGIT_COUNT];
        for i in 0..DIGIT_COUNT {
            public_key_array[i] = public_key_for_digit(secret_key, i as u32);
        }
        public_key_array
    }

    /// Generate the public key for the i-th digit of the message
    fn public_key_for_digit(secret_key: &str, digit_index: u32) -> [u8; HASH160_LENGTH_IN_BYTES] {
        // Convert secret_key from hex string to bytes
        let mut secret_i = match hex_decode(secret_key) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };

        secret_i.push(digit_index as u8);

        let mut hash = hash160::Hash::hash(&secret_i);

        for _ in 0..D {
            hash = hash160::Hash::hash(&hash[..]);
        }

        hash.to_byte_array()
    }

    #[test]
    fn test_winternitz() {
        // The message to sign
        #[rustfmt::skip]
        const MESSAGE: [u8; N0_320] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7, // Big endian
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
        ];

        let script = script! {
            { sign::<N0_320, N1_320>(MY_SECKEY, MESSAGE) }
            { checksig_verify::<N_320, N0_320>(&public_key::<N_320>(MY_SECKEY)) }
        };

        println!(
            "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
            script.len(),
            N0_320 * 4,
            script.len() as f64 / (N0_320 * 4) as f64
        );

        let result = execute_script(script! {
            { sign::<N0_320, N1_320>(MY_SECKEY, MESSAGE) }
            { checksig_verify::<N_320, N0_320>(&public_key::<N_320>(MY_SECKEY)) }
            { digits_to_bytes::<N0_320>() }

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            0xA9 OP_EQUALVERIFY
            0xCB OP_EQUALVERIFY
            0xED OP_EQUALVERIFY
            0x7F OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            0xA9 OP_EQUALVERIFY
            0xCB OP_EQUALVERIFY
            0xED OP_EQUALVERIFY
            0x7F OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            0xA9 OP_EQUALVERIFY
            0xCB OP_EQUALVERIFY
            0xED OP_EQUALVERIFY
            0x7F OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            0xA9 OP_EQUALVERIFY
            0xCB OP_EQUALVERIFY
            0xED OP_EQUALVERIFY
            0x7F OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY
            0x77 OP_EQUAL
        });

        assert!(result.success);
    }

    #[test]
    fn test_winternitz_digits_to_number() {
        // The message to sign
        #[rustfmt::skip]
        let block: u32 = 860033;
        // // 0000 0000 0000 1101 0001 1111 1000 0001
        const MESSAGE: [u8; N0_32] = [0, 0, 0, 13, 1, 15, 8, 1];
        let script = script! {
            { sign::<N0_32, N1_32>(MY_SECKEY, MESSAGE) }
            { checksig_verify::<N_32, N0_32>(&public_key::<N_32>(MY_SECKEY)) }
        };

        println!(
            "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
            script.len(),
            N0_32 * 4,
            script.len() as f64 / (N0_32 * 4) as f64
        );

        let script = script! {
            { sign::<N0_32, N1_32>(MY_SECKEY, MESSAGE) }
            { checksig_verify::<N_32, N0_32>(&public_key::<N_32>(MY_SECKEY)) }
            { digits_to_number::<N0_32>() }
            { block }
            OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_winternitz_digits_to_bytes() {
        // 0000 0000 0000 1101 0001 1111 1000 0001
        // message = [0x0, 0x0, 0x0, 0xD, 0x1, 0xF, 0x8, 0x1]
        let block: u32 = 860033;
        let message: [u8; N0_32] = message_to_digits::<N0_32>(block);
        let script = script! {
            { sign::<N0_32, N1_32>(MY_SECKEY, message) }
            { checksig_verify::<N_32, N0_32>(&public_key::<N_32>(MY_SECKEY)) }
        };

        println!(
            "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
            script.len(),
            N0_32 * 4,
            script.len() as f64 / (N0_32 * 4) as f64
        );

        let result = execute_script(script! {
          { sign::<N0_32, N1_32>(MY_SECKEY, message) }
          { checksig_verify::<N_32, N0_32>(&public_key::<N_32>(MY_SECKEY)) }
          { digits_to_bytes::<N0_32>() }
          0x00
          OP_EQUALVERIFY
          0xD0
          OP_EQUALVERIFY
          0xF1
          OP_EQUALVERIFY
          0x18
          OP_EQUAL
        });

        assert!(result.success);
    }

    // TODO: test the error cases: negative digits, digits > D, ...
}
