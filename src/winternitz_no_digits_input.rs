//
// Winternitz One-time Signatures Hash Only Input
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


// This is an alternative implementation, we dont add the digits as an input, instead we calculate them based on the signature hashes.
// This implementation could help reduce stack usage.

use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};
use hex::decode as hex_decode;

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
// Helper functions
//

/// Generate the public key for the i-th digit of the message
pub fn public_key(secret_key: &str, digit_index: u32) -> Script {
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

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
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
        for i in 0..N {
            { digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) }
        }
    }
}

/// Winternitz Signature verification
/// 
/// Note that the script inputs are malleable.
/// 
/// Optimized by @SergioDemianLerner, @tomkosm
pub fn checksig_verify(secret_key: &str) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..N {

            { public_key(secret_key, N - 1 - digit_index) }

            
            // Check if hash is equal with public key and add digit to altstack.
            // We dont check if a digit was found to save space, incase we have an invalid hash there will be one fewer entry in altstack and OP_FROMALTSTACK later will crash. So its important to start with the altstack empty.
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
        for _ in 1..N0{
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
        for _ in 0..N0 / 2 {
            OP_SWAP
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_ADD
            OP_TOALTSTACK
        }
        for _ in 0..N0 / 2 {
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
        const MESSAGE: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
        ];
        println!(
            "Winternitz signature size: {:?} bytes per 80 bits",
            script! { { sign(MY_SECKEY, MESSAGE) } { checksig_verify(MY_SECKEY) } }.len()
        );

        let script = script! {
            { sign(MY_SECKEY, MESSAGE) }
            { checksig_verify(MY_SECKEY) }

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
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    // TODO: test the error cases: negative digits, digits > D, ...
}