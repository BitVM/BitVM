use std::cmp::min;

use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};
use hex::decode as hex_decode;

const fn log_base_ceil(n: u32, base: u32) -> u32 { //use the fact that base = 2^N and use ilog() to optimize this later 
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    return res;
}

/// Convert a number to digits
pub fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u32> {
    let mut digits = Vec::new();
    if digit_count == -1 {
        while number > 0 {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }   
    } else {
        digits.reserve(digit_count as usize);
        for _ in 0..digit_count {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    }
    digits
}

//This function can change dramatically (for example it can be reversed, those kind of things can reduce the script size a lot but current optimizations are for the straightforward transformation)
pub fn bytes_to_u32s(len:u32, bits_per_item:u32, bytes: &Vec<u8>) -> Vec<u32> {
    assert!(bytes.len() as u32 * 8 <= len * bits_per_item); //I'm not sure if using asserts is fine
    let mut res = vec![0u32; len as usize];
    let mut cur_index: u32 = 0;
    let mut cur_bit: u32 = 0;
    for byte in bytes {
        let mut x: u8 = *byte;
        for _ in 0..8 {
            if cur_bit == bits_per_item {
                cur_bit = 0;
                cur_index += 1;
            }
            res[cur_index as usize] |= ((x & 1) as u32) << cur_bit;
            x >>= 1;
            cur_bit += 1;
        }
    }
    res
}


pub type KeyDigit = [u8; 20];
pub type Key = Vec<KeyDigit>;

pub struct Parameters {
    n0: u32, 
    log_d: u32,
    n1: u32,
    d: u32,  
    n: u32,
    encode_with_digits: bool
}
impl Parameters {
    pub fn new(n0: u32, log_d: u32, encode_with_digits: bool) -> Self {
        assert!((4..=8).contains(&log_d));
        let d: u32 = (1 << log_d) - 1;
        let n1: u32 = log_base_ceil(d * n0, d + 1) + 1;
        let n: u32= n0 + n1;
        Parameters{n0, log_d, n1, d, n, encode_with_digits}
    }
    pub fn byte_message_length(&self) -> u32 {
        return (self.n0 * self.log_d + 7) / 8;
    }
}

/// Generate a public key for the i-th digit of the message
pub fn public_key_for_digit(ps: &Parameters, secret_key: &str, digit_index: u32) -> KeyDigit {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };
    secret_i.push(digit_index as u8);
    let mut hash = hash160::Hash::hash(&secret_i);
    for _ in 0..ps.d {
        hash = hash160::Hash::hash(&hash[..]);
    }
    *hash.as_byte_array()
}

/// Generate a public key from a secret key 
pub fn generate_public_key(ps: &Parameters, secret_key: &str) -> Key {
    let mut public_key = Key::new();
    public_key.reserve(ps.n as usize);
    for i in 0..ps.n {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u32) -> Vec<u8> {
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
pub fn checksum(ps: &Parameters, digits: Vec<u32>) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    ps.d * ps.n0 - sum
}

pub fn get_digits(ps: &Parameters, mut message_digits: Vec<u32>) -> Vec<u32> {
    let mut checksum_digits = to_digits(checksum(ps, message_digits.clone()), ps.d+1, ps.n1 as i32);
    checksum_digits.append(&mut message_digits);
    checksum_digits.reverse();
    checksum_digits
}


pub fn sign_digits(ps: &Parameters, secret_key: &str, message_digits: Vec<u32>) -> Script {
    let digits = get_digits(ps, message_digits);
    if !ps.encode_with_digits {
        script! {
            for i in 0..ps.n {
                { digit_signature(secret_key, i, digits[i as usize]) }
            }
        }
    } else {
        script! {
            for i in 0..ps.n {
                { digit_signature(secret_key, i, digits[i as usize]) }
                { digits[i as usize] }
            }
        }
    }
}

pub fn sign(ps: &Parameters, secret_key: &str, message_bytes: Vec<u8>) -> Script {
    sign_digits(ps, secret_key, bytes_to_u32s(ps.n0, ps.log_d, &message_bytes))
}

fn verify_checksum(ps: &Parameters) -> Script {
    script! {

        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..ps.n0 {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { ps.d as u32 * ps.n0 }
        OP_ADD


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..ps.n1 - 1 {
            for _ in 0..ps.log_d {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }
        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY
    }
}


/*
    This is exactly the same as the previous winternitz signature check
    Stack Size: Close to the theoretic limit 
    Max Stack Depth: ~(2 * N + D)
    Format: With digits
    Security: It crashes or a OP_VERIFY fails if the input is malicious
*/
fn verify_digits_deepstack(ps: &Parameters, public_key: &Key) -> Script {
    assert!(ps.encode_with_digits);
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..ps.n {
            // Verify that the digit is in the range [0, d]
            // See https://github.com/BitVM/BitVM/issues/35
            { ps.d }
            OP_MIN                

            // Push two copies of the digit onto the altstack
            OP_DUP
            OP_TOALTSTACK
            OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            for _ in 0..ps.d {
                OP_DUP OP_HASH160
            }

            // Verify the signature for this digit
            OP_FROMALTSTACK
            OP_PICK
            { (public_key[ps.n as usize - 1 - digit_index as usize]).to_vec() }
            OP_EQUALVERIFY

            // Drop the d+1 stack items
            for _ in 0..(ps.d + 1)/2 {
                OP_2DROP
            } 
        }
    }
}

/*
    This is exactly the same as the previous winternitz compact signature check
    Stack Size: ~(N * (10 + 8 * D))
    Max Stack Depth: ~N
    Format: Without digits
    Security: It crashes or a OP_VERIFY fails if the input is malicious
*/
fn verify_digits_trial(ps: &Parameters, public_key: &Key) -> Script {
    assert!(!ps.encode_with_digits);
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..ps.n {

            { public_key[(ps.n - 1 - digit_index) as usize].to_vec() }


            // Check if hash is equal with public key and add digit to altstack.
            // We dont check if a digit was found to save space, incase we have an invalid hash
            // there will be one fewer entry in altstack and OP_FROMALTSTACK later will crash.
            // So its important to start with the altstack empty.
            // TODO: add testcase for this.
            OP_SWAP

            OP_2DUP
            OP_EQUAL

            OP_IF

                {ps.d}

                OP_TOALTSTACK

            OP_ENDIF

            for i in 0..ps.d {

                OP_HASH160

                OP_2DUP

                OP_EQUAL

                OP_IF

                    {ps.d-i-1}
                    OP_TOALTSTACK

                OP_ENDIF
            }
            
            OP_2DROP
        }
    }
}


/*
    This uses the fact that using OP_IF's in each for iteration is not necessary, so does the for loop with binary search
    Stack Size: ~(N * (9 + LOG_D * 11 + D))
    Max Stack Depth: ~(2 * N)
    Format: With digits
    Security: OP_VERIFY fails if the input is malicious
*/
fn verify_digits_binary_search(ps: &Parameters, public_key: &Key) -> Script {
    assert!(ps.encode_with_digits);
    script! {
        for digit_index in 0..ps.n {
            //{ ps.d }
            //OP_MIN 
            //these are not necessary 
            OP_DUP
            OP_TOALTSTACK
            {ps.d}
            OP_SWAP OP_SUB
            for bit in (0..ps.log_d).rev() { 
                {1 << bit}
                OP_2DUP
                OP_GREATERTHANOREQUAL
                OP_IF
                    OP_ROT
                    for _ in 0..(1<<bit) {
                        OP_HASH160
                    }
                    OP_ROT OP_ROT
                    OP_SUB
                    OP_DUP
                OP_ENDIF
                OP_DROP
            }
            OP_DROP
            { (public_key[(ps.n - 1 - digit_index) as usize]).to_vec() }
            OP_EQUALVERIFY
        }
    }
}


/* 
    This turns the final output digits to bytes
    Uses a lookup table to divide the numbers to two 
    This is inefficient for small N and D due to the cost of the table
    Works assuming 4 <= log_d <= 8, it doesn't work on other constraints
*/
fn turn_message_to_bytes_deepstack(ps: &Parameters) -> Script {
    let mut turning_into_bytes = script! {};
    if ps.log_d == 8 {
        //already bytes
        turning_into_bytes = script! {};
    } else if ps.log_d == 4 {
        turning_into_bytes = script! {
            for i in 0..ps.n0 / 2 {
                OP_SWAP
                for _ in 0..ps.log_d {
                    OP_DUP OP_ADD
                }
                OP_ADD
                // Push all bytes to the altstack, except for the last byte
                if i != (ps.n0/2) - 1 {
                    OP_TOALTSTACK
                }
            }
            // Read the bytes from the altstack
            for _ in 0..ps.n0 / 2 - 1{
                OP_FROMALTSTACK
            }
        };
    } else {
        turning_into_bytes = script! {
            //create division by two table i.e. table(x) = floor(x/2)
            {ps.d/2}
            for i in 1..(ps.d+1)/2 {
                OP_DUP OP_DUP
                OP_1SUB
            }
            OP_DUP
        };
        //convert
        let mut current_byte_len = 0;
        let mut script_lines = vec![];
        script_lines.push(script! {
            OP_0
            OP_TOALTSTACK
        });
        for i in 0..ps.n0 {
            let mut left = ps.log_d;
            script_lines.push(script! {
                {ps.d + 1} OP_ROLL
            });                
            while left > 0 {
                if current_byte_len == 8 {
                    current_byte_len = 0;
                    script_lines.push(script! {
                        OP_0
                        OP_TOALTSTACK
                    });
                }
                let take = min(left, 8 - current_byte_len);
                script_lines.push(script! {
                    OP_DUP
                    OP_TOALTSTACK
                    for _ in 0..take {
                        OP_PICK
                    }
                    OP_DUP
                    for _ in 0..take {
                        OP_DUP OP_ADD
                    }
                    OP_FROMALTSTACK
                    OP_SWAP OP_SUB
                    for _ in 0..current_byte_len {
                        OP_DUP OP_ADD
                    }
                    OP_FROMALTSTACK
                    OP_ADD
                    OP_TOALTSTACK
                }); 
                current_byte_len += take;
                left -= take;
            } 
            script_lines.push(script! {
                OP_DROP
            });
        }
        //clear the table
        script_lines.push (script! {
            for _ in 0..(ps.d + 1)/2 {
                OP_2DROP
            }
            for _ in 0..ps.byte_message_length() {
                OP_FROMALTSTACK
            }
        });
        for script_line in script_lines {
            turning_into_bytes = turning_into_bytes.push_script(script_line.compile());
        }
    }
    turning_into_bytes
}


/* 
    This turns the final output digits to bytes
    Uses straightforward comparisons for the job
    Works assuming 4 <= log_d <= 8, it doesn't work on other constraints
*/
fn turn_message_to_bytes_compact(ps: &Parameters) -> Script {
    let mut turning_into_bytes = script! {};
    if ps.log_d == 8 {
        //a..ps.log_dlready bytes
        turning_into_bytes = script! {};
    } else if ps.log_d == 4 {
        turning_into_bytes = script! {
            for i in 0..ps.n0 / 2 {
                OP_SWAP
                for _ in 0..ps.log_d {
                    OP_DUP OP_ADD
                }
                OP_ADD
                // Push all bytes to the altstack, except for the last byte
                if i != (ps.n0/2) - 1 {
                    OP_TOALTSTACK
                }
            }
            // Read the bytes from the altstack
            for _ in 0..ps.n0 / 2 - 1{
                OP_FROMALTSTACK
            }
        };
    } else {
        //convert
        let mut lens: Vec<u32> = vec![];
        let mut script_lines: Vec<Script> = vec![];
        for i in 0..ps.n0 {
            let start = i * ps.log_d;
            let next_stop = start + 8 - (start % 8);
            let split = next_stop - start;
            if split >= ps.log_d {
                lens.push(ps.log_d);
                script_lines.push(script! {
                    OP_TOALTSTACK
                });
            } else {
                lens.push(split);
                lens.push(ps.log_d - split);
                script_lines.push(script! {
                    OP_0 
                    for j in (split..ps.log_d).rev() {
                        if j != ps.log_d - 1 {
                            OP_DUP OP_ADD
                        }
                        OP_SWAP
                        {1 << j}
                        OP_2DUP
                        OP_GREATERTHANOREQUAL
                        OP_IF
                            OP_SUB
                            OP_SWAP
                            OP_1ADD
                            OP_SWAP
                            OP_DUP
                        OP_ENDIF
                        OP_DROP
                        OP_SWAP
                    }
                    OP_SWAP
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                });
            }
        }
        lens.reverse();        
        let mut last_bytes =  (8 - (ps.n0 * ps.log_d % 8)) % 8;
        let mut is_last_zero = true;
        script_lines.push(script! {
            OP_0
        });
        for i in 0..lens.len() {
            let l = lens[i];
            if last_bytes >= 8 {
                assert!(last_bytes == 8);
                last_bytes = 0;
                script_lines.push(script! {
                    OP_0
                });
                is_last_zero = true;
            }
            if !is_last_zero {
                script_lines.push(script! {
                    for _ in 0..l {
                        OP_DUP OP_ADD
                    }
                });
            }
            is_last_zero = false;
            script_lines.push(script! { 
                OP_FROMALTSTACK
                OP_ADD
            });
            last_bytes += l;
        }
         
        for script_line in script_lines {
            turning_into_bytes = turning_into_bytes.push_script(script_line.compile());
        }
        
    }
    turning_into_bytes
}


/*
    verification_algorithm:
        0: verify_digits_deepstack
        1: verify_digits_trial 
        2: verify_digits_binary_search
    conversion_algorithm: 
        0: turn_message_to_bytes_deepstack
        1: turn_message_to_bytes_compact
*/
pub fn checksig_verify(ps: &Parameters, public_key: &Key, verification_algorithm: u8, conversion_algorithm: u8) -> Script {
    let mut signature_check = script!{};
    if verification_algorithm == 0 {
        signature_check = verify_digits_deepstack(ps, public_key);
    } else if verification_algorithm == 1 {
        signature_check = verify_digits_trial(ps, public_key);
    } else if verification_algorithm == 2 {
        signature_check = verify_digits_binary_search(ps, public_key);
    } else {
        assert!(false);
    }
    let mut turning_into_bytes = script!{};
    if conversion_algorithm == 0 {
        turning_into_bytes = turn_message_to_bytes_deepstack(ps);
    } else if conversion_algorithm == 1 {
        turning_into_bytes = turn_message_to_bytes_compact(ps);
    } else {
        assert!(false);
    }
    signature_check = signature_check.push_script(verify_checksum(ps).compile());
    signature_check.push_script(turning_into_bytes.compile())
}


#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use super::*;
    #[test]
    fn test_winternitz() {
        const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let mut prng = ChaCha20Rng::seed_from_u64(37);
        // The message to sign
        for _ in 0..100 {
            let mut ps = Parameters::new(prng.gen_range(1..200), prng.gen_range(4..=8), false);
            let message_byte_size = ps.n0 * ps.log_d / 8;
            let mut message = vec![0u8; message_byte_size as usize];
            let mut return_message = vec![];
            return_message.resize(ps.byte_message_length() as usize,0);
            for i in 0..message_byte_size {
                message[i as usize] = prng.gen_range(0u8..=255);
                return_message[i as usize] = message[i as usize];
            }
            //let message_digits = bytes_to_u32s(ps.n0, ps.log_d, &message);
            let public_key = generate_public_key(&ps, MY_SECKEY);
            for verification_algorithm in 0..3 {
                for conversion_algorithm in 0..2 {
                    ps.encode_with_digits = verification_algorithm != 1;
                    let script = script! {
                        { sign(&ps, MY_SECKEY, message.clone()) }
                        { checksig_verify(&ps, &public_key, verification_algorithm, conversion_algorithm) }
                    };
                    println!(
                        "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
                        script.len(),
                        ps.n0 * 4,
                        script.len() as f64 / (ps.n0 * 4) as f64
                    );
                    assert!(execute_script(script! {
                        { sign(&ps, MY_SECKEY, message.clone()) }
                        { checksig_verify(&ps, &public_key, verification_algorithm, conversion_algorithm) }
                        for i in 0..ps.byte_message_length() {
                            {return_message[i as usize]}
                            if i == ps.byte_message_length() - 1 {
                                OP_EQUAL
                            } else {
                                OP_EQUALVERIFY
                            }
                        }
                        
                    }).success);
                }
            }
        }
    }
    //There are no failing test cases still, states of being in the TODO continues
}