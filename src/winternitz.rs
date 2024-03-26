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

use crate::treepp::{pushable, script, unroll, Script};
use bitcoin::hashes::{ripemd160, Hash};
use hex::decode as hex_decode; // Add `hex` crate to your dependencies

/// Bits per digit
const LOG_D: u32 = 4;
/// Digits are base d+1
pub const D: u32 = (1 << LOG_D) - 1;
/// Number of digits of the message
const N0: u32 = 20;
/// Number of digits of the checksum
const N1: usize = 4;
/// Total number of digits to be signed
const N: u32 = N0 + N1 as u32;

//
// Helper Functions
//

/// Generate the public key for the i-th digit of the message
pub fn public_key(secret_key: &str, digit_index: u32) -> Script {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = ripemd160::Hash::hash(&secret_i);

    for _ in 0..D {
        hash = ripemd160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
    }
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u8) -> Script {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = ripemd160::Hash::hash(&secret_i);

    for _ in 0..message_digit {
        hash = ripemd160::Hash::hash(&hash[..]);
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
pub fn sign(secret_key: &str, message_digits: [u8; N0 as usize]) -> Script {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    script! {
        { unroll(N, |i| script! { 
            { digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) }
        })}
    }

    // return sig.reverse().map( (m,i) => digit_signature(secret_key, i, m))
}

///  Locking Script
pub fn checksig_verify(secret_key: &str) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        {unroll(N, |digit_index| script!{
            // Verify that the digit is in the range [0, d]
            OP_DUP
            0
            { D+1 }
            OP_WITHIN
            OP_VERIFY

            // Push two copies of the digit onto the altstack
            OP_DUP
            OP_TOALTSTACK
            OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            { unroll(D, |_| script!{ OP_DUP OP_RIPEMD160 } ) }

            // Verify the signature for this digit
            OP_FROMALTSTACK
            OP_PICK
            { public_key(secret_key, N - 1 - digit_index) }
            OP_EQUALVERIFY

            // Drop the d+1 stack items
            { unroll((D+1)/2, |_| script!{OP_2DROP}) }
        })}




        //
        // Verify the Checksum
        //

        // 1. Compute the checksum of the message's digits
        0
        { unroll(N0, |_| script! {OP_FROMALTSTACK OP_DUP OP_ROT OP_ADD} ) }
        { D * N0 }
        OP_SWAP
        OP_SUB


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        { unroll(N1 as u32 - 1, |_| script! {
            { unroll(LOG_D, |_| script!{OP_DUP OP_ADD}) }
            OP_FROMALTSTACK
            OP_ADD
        })}

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY


        // Convert the message's digits to bytes
        { unroll(N0/2, |_| script! {
            OP_SWAP
            { unroll(LOG_D, |_| script! {OP_DUP OP_ADD}) }
            OP_ADD
            OP_TOALTSTACK
        }) }
        { unroll(N0/2, |_| script! {OP_FROMALTSTACK}) }

    }
}
