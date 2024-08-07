//
// Winternitz One-time Signatures
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

/// Bits per digit
const LOG_D: u32 = 4;
/// Digits are base d+1
pub const D: u32 = (1 << LOG_D) - 1;
/// Number of digits of the message
const N0: u32 = 40;
/// Number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
const N1: usize = 4;
/// Total number of digits to be signed
const N: u32 = N0 + N1 as u32;
/// The public key type
pub type PublicKey = [[u8; 20]; N as usize];

//
// Helper functions
//

/// Generate a public key for the i-th digit of the message
pub fn public_key_for_digit(secret_key: &str, digit_index: u32) -> [u8; 20] {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..=D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    *hash.as_byte_array()
}

/// Generate a public key from a secret key
pub fn generate_public_key(secret_key: &str) -> PublicKey {
    let mut public_key_array = [[0u8; 20]; N as usize];
    for i in 0..N {
        public_key_array[i as usize] = public_key_for_digit(secret_key, i);
    }
    public_key_array
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u8) -> Script {
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

    script! {
        { hash_bytes }
        { message_digit }
    }
}

/// Compute the checksum of the message's digits.
/// Further infos in chapter "A domination free function for Winternitz signatures"
pub fn checksum(digits: [u8; N0 as usize]) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    D * N0 - sum
}

/// Convert a number to digits
pub fn to_digits<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D + 1);
        number = (number - digit) / (D + 1);
        digits[i] = digit as u8;
    }
    digits
}

/// Compute the signature for a given message
pub fn sign_digits(secret_key: &str, message_digits: [u8; N0 as usize]) -> Script {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    script! {
        for i in 0..N {
            { digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) }
        }
    }
}

pub fn sign(secret_key: &str, message_bytes: &[u8]) -> Script {
    // Convert message to digits
    let mut message_digits = [0u8; 20 * 2 as usize];
    for (digits, byte) in message_digits.chunks_mut(2).zip(message_bytes) {
        digits[0] = byte & 0b00001111;
        digits[1] = byte >> 4;
    }

    sign_digits(secret_key, message_digits)
}

pub fn checksig_verify(public_key: &PublicKey) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //
        // Repeat this for every of the n many digits
        for digit_index in 0..N {
            // Verify that the digit is in the range [0, d]
            // See https://github.com/BitVM/BitVM/issues/35
            { D }
            OP_MIN

            // Push two copies of the digit onto the altstack
            OP_DUP
            OP_TOALTSTACK
            OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            for _ in 0..=D {
                OP_DUP OP_HASH160
            }
            // Verify the signature for this digit
            OP_FROMALTSTACK
            OP_ROLL
            { public_key[N as usize - 1 - digit_index as usize].to_vec() }
            OP_EQUALVERIFY

            // Drop the d+1 stack items
            for _ in 0..(D+1)/2 {
                OP_2DROP
            }
        }

        //
        // Verify the Checksum
        //

        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..N0 {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * N0 }
        OP_ADD


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..N1 - 1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY


        // Convert the message's digits to bytes
        for i in 0..N0 / 2 {
            OP_SWAP
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_ADD
            // Push all bytes to the altstack, except for the last byte
            if i != (N0/2) - 1 {
                OP_TOALTSTACK
            }
        }
        // Read the bytes from the altstack
        for _ in 0..N0 / 2 - 1{
            OP_FROMALTSTACK
        }

    }
}

/// Decrease in input stack requirement by 55% by
/// increasing the script size by 65%. This is extremely valuable
/// as it allows passing more data by only marginally increasing script size.
/// Marginally, because the stack:script limits ratio is 1:400 for standard
/// transaction. It's 1:410 if we consider entire available block space.
/// The optimized version has lower stack utilization per unit of script than
/// the un-optimized version.
pub fn stack_optimized_digit_signature(
    secret_key: &str,
    digit_index: u32,
    message_digit: u8,
) -> Script {
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

    script! {
        { hash_bytes }
    }
}

pub fn stack_optimized_sign_digits(secret_key: &str, message_digits: [u8; N0 as usize]) -> Script {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());
    script! {
        for i in 0..N {
            { stack_optimized_digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) }
        }
    }
}

pub fn stack_optimized_checksig_verify(public_key: &PublicKey) -> Script {
    script! {
        for digit_index in 0..N {
            { public_key[N as usize - 1 - digit_index as usize].to_vec() } OP_SWAP
            for j in 0..=D {
                OP_HASH160 OP_2DUP
                OP_EQUAL
                OP_IF {D - j} OP_TOALTSTACK OP_ENDIF
            }
            OP_2DROP
        }

        // compute checksum
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..N0 {
                OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * N0 }
        OP_ADD

        // pre-computed checksum
        OP_FROMALTSTACK
        for _ in 1..N1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK OP_ADD
        }
        OP_EQUALVERIFY

        // Convert the message's digits to bytes
        for i in 0..N0 / 2 {
            OP_SWAP
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_ADD
            // Push all bytes to the altstack, except for the last byte
            if i != (N0/2) - 1 {
                OP_TOALTSTACK
            }
        }
        // Read the bytes from the altstack
        for _ in 0..N0 / 2 - 1{
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // The secret key
    const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_winternitz() {
        // The message to sign
        #[rustfmt::skip]
        const MESSAGE: [u8; N0 as usize] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
        ];

        let public_key = generate_public_key(MY_SECKEY);

        let script = script! {
            { sign_digits(MY_SECKEY, MESSAGE) }
            { checksig_verify(&public_key) }
        };

        println!(
            "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit \n\t@ Max stack usage of {} elements",
            script.len(),
            N0 * 4,
            script.len() as f64 / (N0 * 4) as f64,
            execute_script(script.clone()).stats.max_nb_stack_items
        );

        run(script! {
            { script }

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
    }

    #[test]
    fn test_stack_optimized_winternitz() {
        // The message to sign
        #[rustfmt::skip]
        const MESSAGE: [u8; N0 as usize] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
        ];

        let public_key = generate_public_key(MY_SECKEY);

        let script = script! {
            { stack_optimized_sign_digits(MY_SECKEY, MESSAGE) }
            { stack_optimized_checksig_verify(&public_key) }
        };

        println!(
            "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit \n\t@ Max stack usage of {} elements",
            script.len(),
            N0 * 4,
            script.len() as f64 / (N0 * 4) as f64,
            execute_script(script.clone()).stats.max_nb_stack_items
        );

        run(script! {
            { script }

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
    }

    // TODO: test the error cases: negative digits, digits > D, ...
}
