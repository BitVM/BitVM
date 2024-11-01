use std::cmp::min;

use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};
use hex::decode as hex_decode;

const fn log_base_ceil(n: u32, base: u32) -> u32 { 
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    return res;
}

fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u32> {
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
fn bytes_to_u32s(len:u32, bits_per_item:u32, bytes: &Vec<u8>) -> Vec<u32> {
    assert!(bytes.len() as u32 * 8 <= len * bits_per_item); 
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

type KeyDigit = [u8; 20];
pub type Key = Vec<KeyDigit>;

pub struct Parameters {
    n0: u32, 
    log_d: u32,
    n1: u32,
    d: u32,  
    n: u32,
}
impl Parameters {
    pub fn new(n0: u32, log_d: u32) -> Self {
        assert!((4..=8).contains(&log_d));
        let d: u32 = (1 << log_d) - 1;
        let n1: u32 = log_base_ceil(d * n0, d + 1) + 1;
        let n: u32= n0 + n1;
        Parameters{n0, log_d, n1, d, n}
    }
    fn byte_message_length(&self) -> u32 {
        return (self.n0 * self.log_d + 7) / 8;
    }
}

/// Generate a public key for the i-th digit of the message
fn public_key_for_digit(ps: &Parameters, secret_key: &str, digit_index: u32) -> KeyDigit {
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


/// Generate a public key from a secret key 
pub fn generate_public_key(ps: &Parameters, secret_key: &str) -> Key {
    let mut public_key = Key::new();
    public_key.reserve(ps.n as usize);
    for i in 0..ps.n {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

fn checksum(ps: &Parameters, digits: Vec<u32>) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    ps.d * ps.n0 - sum
}

fn add_message_checksum(ps: &Parameters, mut digits: Vec<u32>) -> Vec<u32> {
    let mut checksum_digits = to_digits(checksum(ps, digits.clone()), ps.d+1, ps.n1 as i32);
    checksum_digits.append(&mut digits);
    checksum_digits.reverse();
    checksum_digits
}


/*
    verifier: These are signature verifiers
        0: 
            Tag: Listpick 
            Description: This generates hashes for each possible value and then uses OP_PICK 
            to get the corresponding one from the created list. Also as a small improvement, it
            divides the length of the list by 2 in the start

            Signature format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0

            Approximate Max Stack Depth: 2N + D/2

        1: 
            Tag: Bruteforce 
            Description: This tries each possible value straightforwardly

            Signature format: hash_{n - 1}, hash_{n - 2} ... hash_0

            Approximate Max Stack Depth: N

        2:
            Tag: Binary search
            Description: This simulates a for loop of hashing using binary search on the digit

            Signature format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0

            Approximate Max Stack Depth: 2N

        3: 
            Tag: Hybrid
            Descripton: This narrows the search space first by doing binary search, then uses a list for the remaning space 
            i.e. it uses Algorithm 2 and Algorithm 0 consequently
            
            Signature format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0

            Approximate Max Stack Depth: 2N + REMAINING_SPACE_SIZE
    
    CONVERTER: These are digits to bytes converters
        0: 
            Tag: Tabled
            Descripton: This uses a table for the divison of 2
            
            Approximate Max Stack Depth: N + D

        1: 
            Tag: Straightforward
            Descripton: This just uses OP_IF's to decompose the numbers into bits

            Approximate Max Stack Depth: N

*/
pub struct WinternitzOperator<const VERIFIER:u8, const CONVERTER:u8> {

}

impl<const VERIFIER:u8, const CONVERTER:u8> 
WinternitzOperator<VERIFIER, CONVERTER> {
    pub fn sign_digits(&self, ps: &Parameters, secret_key: &str, digits: Vec<u32>) -> Script {
        let digits = add_message_checksum(ps, digits);
        if VERIFIER == 1 {
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

    pub fn sign(&self, ps: &Parameters, secret_key: &str, message_bytes: &Vec<u8>) -> Script {
        self.sign_digits(ps, secret_key, bytes_to_u32s(ps.n0, ps.log_d, &message_bytes))
    }    


    fn verify_checksum(&self, ps: &Parameters) -> Script {
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

    fn convert_to_bytes(&self, ps : &Parameters) -> Script {
        let mut turning_into_bytes = script! {};
        if CONVERTER == 0 {
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
                        if i != (ps.n0/2) - 1 {
                            OP_TOALTSTACK
                        }
                    }
                    for _ in 0..ps.n0 / 2 - 1{
                        OP_FROMALTSTACK
                    }
                };
            } else {
                turning_into_bytes = script! {
                    //create division by two table i.e. table(x) = floor(x/2)
                    {ps.d/2}
                    for _ in 1..(ps.d+1)/2 {
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
                for _ in 0..ps.n0 {
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
        } else if CONVERTER == 1 {
            if ps.log_d == 8 {
                turning_into_bytes = script! {};
            } else if ps.log_d == 4 {
                turning_into_bytes = script! {
                    for i in 0..ps.n0 / 2 {
                        OP_SWAP
                        for _ in 0..ps.log_d {
                            OP_DUP OP_ADD
                        }
                        OP_ADD
                        if i != (ps.n0/2) - 1 {
                            OP_TOALTSTACK
                        }
                    }
                    for _ in 0..ps.n0 / 2 - 1{
                        OP_FROMALTSTACK
                    }
                };
            } else {
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
        } else {
            assert!(false, "No converter with the given index");
        }
        turning_into_bytes
    }
}

impl<const CONVERTER:u8> 
WinternitzOperator<0, CONVERTER> {
    fn verify_digits<const IS_SUS: bool>(&self, ps: &Parameters, public_key: &Key) -> Script {
        script! {
            for digit_index in 0..ps.n {
                if IS_SUS {
                    // See https://github.com/BitVM/BitVM/issues/35
                    { ps.d }
                    OP_MIN                
                }
                OP_DUP
                OP_TOALTSTACK
                { (ps.d + 1) / 2 }
                OP_2DUP
                OP_LESSTHAN
                OP_IF
                    OP_DROP
                    OP_TOALTSTACK
                    for _ in 0..(ps.d + 1) / 2  {
                        OP_HASH160
                    }
                OP_ELSE
                    OP_SUB
                    OP_TOALTSTACK
                OP_ENDIF
                for _ in 0..ps.d/2 {
                    OP_DUP OP_HASH160
                }
                OP_FROMALTSTACK
                OP_PICK
                { (public_key[ps.n as usize - 1 - digit_index as usize]).to_vec() }
                OP_EQUALVERIFY    
                for _ in 0..(ps.d + 1)/4 {
                    OP_2DROP
                } 
            }
        }
    }

    pub fn checksig_verify<const IS_SUS: bool>(&self, ps: &Parameters, public_key: &Key) -> Script {
        let mut script = self.verify_digits::<IS_SUS>(ps, public_key);
        script = script.push_script(self.verify_checksum(ps).compile());
        script.push_script(self.convert_to_bytes(ps).compile())
    }
}

impl<const CONVERTER:u8> 
WinternitzOperator<1, CONVERTER> {
    fn verify_digits<const IS_SUS: bool> (&self, ps: &Parameters, public_key: &Key) -> Script {
        if !IS_SUS {
            script! {
                for digit_index in 0..ps.n {
                    { public_key[(ps.n - 1 - digit_index) as usize].to_vec() }
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
        } else {
            script! {
                for digit_index in 0..ps.n {
                    { public_key[(ps.n - 1 - digit_index) as usize].to_vec() }
                    OP_SWAP
                    { -1 } OP_TOALTSTACK
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
                    OP_FROMALTSTACK 
                    OP_DUP
                    { -1 } 
                    OP_NUMNOTEQUAL OP_VERIFY
                    OP_FROMALTSTACK OP_DROP
                    OP_TOALTSTACK
                }
            }
        }
    }

    pub fn checksig_verify<const IS_SUS: bool>(&self, ps: &Parameters, public_key: &Key) -> Script {
        let mut script = self.verify_digits::<IS_SUS>(ps, public_key);
        script = script.push_script(self.verify_checksum(ps).compile());
        script.push_script(self.convert_to_bytes(ps).compile())
    }
}

impl<const CONVERTER:u8> 
WinternitzOperator<2, CONVERTER> {
    fn verify_digits<const IS_SUS: bool> (&self, ps: &Parameters, public_key: &Key) -> Script {
        script! {
            for digit_index in 0..ps.n {
                /* 
                if IS_SUS {
                    { ps.d }
                    OP_MIN 
                }
                */ 
                //this shouldn't be necessary as the digits can only go one way with this
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

    pub fn checksig_verify<const IS_SUS: bool>(&self, ps: &Parameters, public_key: &Key) -> Script {
        let mut script = self.verify_digits::<IS_SUS>(ps, public_key);
        script = script.push_script(self.verify_checksum(ps).compile());
        script.push_script(self.convert_to_bytes(ps).compile())
    }
}

impl<const CONVERTER:u8> 
WinternitzOperator<3, CONVERTER> {
    fn verify_digits<const IS_SUS: bool> (&self, ps: &Parameters, public_key: &Key, block_log_d: u32) -> Script {
        let block_d = (1 << block_log_d) - 1;
        script! {
            for digit_index in 0..ps.n {
                if IS_SUS {
                    { ps.d }
                    OP_MIN 
                }
                OP_DUP
                OP_TOALTSTACK
                {ps.d} OP_SWAP OP_SUB
                for bit in (block_log_d..ps.log_d).rev() { 
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
                {block_d} OP_SWAP OP_SUB //turn to positive form
                OP_TOALTSTACK
                for _ in 0..block_d {
                    OP_DUP
                    OP_HASH160
                }
                OP_FROMALTSTACK
                OP_PICK
                { (public_key[(ps.n - 1 - digit_index) as usize]).to_vec() }
                OP_EQUALVERIFY
                for _ in 0..((block_d + 1)/2) {
                    OP_2DROP
                }
            }
        }
    }

    pub fn checksig_verify<const IS_SUS: bool>(&self, ps: &Parameters, public_key: &Key, block_log_d: u32) -> Script {
        assert!((1..=block_log_d).contains(&block_log_d));
        let mut script = self.verify_digits::<IS_SUS>(ps, public_key, block_log_d);
        script = script.push_script(self.verify_checksum(ps).compile());
        script.push_script(self.convert_to_bytes(ps).compile())
    }
}


#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use super::*;
    use std::sync::Mutex;
    lazy_static::lazy_static! {
        static ref MALICIOUS_RNG: Mutex<ChaCha20Rng> = Mutex::new(ChaCha20Rng::seed_from_u64(337)); 
    }

    const TEST_COUNT: u32 = 100;
    const VERIFIER_TAGS: [&str; 4] = ["Listpick", "Bruteforce", "Binarysearch", "Hybrid"];
    const CONVERTER_TAGS: [&str; 2] = ["Tabled", "Straightforward"];

    //This test is not very extensive and definitely misses corner cases, if there is any
    fn try_malicious(ps: &Parameters, verifier: u32) -> Script {
        let mut rng = MALICIOUS_RNG.lock().unwrap();
        let ind = rng.gen_range(0..ps.n);
        if verifier == 1 {
            script! {
                for _ in 0..ind {
                    OP_TOALTSTACK
                }
                for _ in 0..(rng.gen_range(1..20)) {
                    OP_HASH160
                }                for _ in 0..ind {
                    OP_FROMALTSTACK
                }
            }
        } else {
            let type_of_action = rng.gen_range(0..2);
            script! {
                for _ in 0..ind {
                    OP_TOALTSTACK OP_TOALTSTACK
                }
                if type_of_action == 0 {
                    OP_DROP {-1}
                } else {
                    OP_TOALTSTACK
                    for _ in 0..(rng.gen_range(1..20)) {
                        OP_HASH160
                    }
                    OP_FROMALTSTACK
                }
                for _ in 0..ind {
                    OP_FROMALTSTACK OP_FROMALTSTACK
                }
            }
        }
    }

    macro_rules! test_script {
        ($ps:expr, $s:expr, $message_checker:expr, $desired_outcome:expr) => {
            println!(
                "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit\n",
                $s.len(),
                $ps.n0 * $ps.log_d,
                $s.len() as f64 / ($ps.n0 * $ps.log_d) as f64
            );
            assert!(execute_script($s.push_script($message_checker.clone().compile())).success == $desired_outcome);
        };
    }
    macro_rules! generate_regular_winternitz_tests {
        (
            $ps:expr, $public_key:expr, $message:expr, $message_checker:expr, $desired_outcome:expr;
            $([$verifier:expr, $converter:expr, $is_sus:ident]),*
        ) => {
            $(
                {
                    let o = WinternitzOperator::<$verifier, $converter> {};
                    let s = script! {
                        { o.sign(&$ps, MY_SECKEY, &$message) }
                        if $desired_outcome == false {
                             { try_malicious($ps, $verifier) }
                        }
                        { o.checksig_verify::<{$is_sus}>(&$ps, &$public_key) }
                    };

                    println!("For N0:{} and LOG_D:{}  {} verifier with converter:{} is_sus:{} =>", $ps.n0, $ps.log_d, VERIFIER_TAGS[$verifier], CONVERTER_TAGS[$converter], $is_sus);
                    test_script!($ps, s, $message_checker, $desired_outcome);
                }
            )*
        };
    }
    macro_rules! generate_hybrid_winternitz_tests {
        (
            $ps:expr, $public_key:expr, $message:expr, $message_checker:expr, $desired_outcome:expr;
            $([$converter:expr, $is_sus:ident]),*
        ) => {
            $(
                {
                    let o = WinternitzOperator::<3, $converter> {};
                    for i in 1..=$ps.log_d {
                        let s = script! {
                            { o.sign(&$ps, MY_SECKEY, &$message) }
                            if $desired_outcome == false {
                                { try_malicious($ps, 3) }
                           }
                            { o.checksig_verify::<{$is_sus}>(&$ps, &$public_key, i) }
                        };
                        println!("For N0:{} and LOG_D:{}  {} verifier with converter:{} is_sus:{} block_log_d:{} =>", $ps.n0, $ps.log_d, VERIFIER_TAGS[3], CONVERTER_TAGS[$converter], $is_sus, i);
                        test_script!($ps, s, $message_checker, $desired_outcome);
                    }
                }
            )*
        };
    }
   
    #[test]
    fn test_winternitz_success() {
        const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let mut prng = ChaCha20Rng::seed_from_u64(37);
        for _ in 0..TEST_COUNT {
            let ps = Parameters::new(prng.gen_range(1..256), prng.gen_range(4..=8));
            let message_byte_size = ps.n0 * ps.log_d / 8;
            let mut message = vec![0u8; message_byte_size as usize];
            let mut return_message = vec![0; ps.byte_message_length() as usize];
            for i in 0..message_byte_size {
                message[i as usize] = prng.gen_range(0u8..=255);
                return_message[i as usize] = message[i as usize];
            }
            let public_key = generate_public_key(&ps, MY_SECKEY);
            let message_checker = script! {
                for i in 0..ps.byte_message_length() {
                    {return_message[i as usize]}
                    if i == ps.byte_message_length() - 1 {
                        OP_EQUAL
                    } else {
                        OP_EQUALVERIFY
                    }
                }
            };
            generate_regular_winternitz_tests!(
                &ps, public_key, message, message_checker, true;
                [0, 0, false],
                [0, 0, true],
                [0, 1, false],
                [0, 1, true],
                [1, 0, false],
                [1, 0, true],
                [1, 1, false],
                [1, 1, true],
                //[2, 0, false], //these two cases are not necessary as binary search algorithm doesn't have any extra operations for malicious signatures for now
                [2, 0, true],
                //[2, 1, false],
                [2, 1, true]
            );
            generate_hybrid_winternitz_tests!(
                &ps, public_key, message, message_checker, true;
                [0, false],
                [0, true],
                [1, false],
                [1, true]
            );
        }
    }

    #[test]
    fn test_winternitz_fail() {
        const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let mut prng = ChaCha20Rng::seed_from_u64(37);
        for _ in 0..TEST_COUNT {
            let ps = Parameters::new(prng.gen_range(1..256), prng.gen_range(4..=8));
            let message_byte_size = ps.n0 * ps.log_d / 8;
            let mut message = vec![0u8; message_byte_size as usize];
            let mut return_message = vec![0; ps.byte_message_length() as usize];
            for i in 0..message_byte_size {
                message[i as usize] = prng.gen_range(0u8..=255);
                return_message[i as usize] = message[i as usize];
            }
            let public_key = generate_public_key(&ps, MY_SECKEY);
            let message_checker = script! {
                for i in 0..ps.byte_message_length() {
                    {return_message[i as usize]}
                    if i == ps.byte_message_length() - 1 {
                        OP_EQUAL
                    } else {
                        OP_EQUALVERIFY
                    }
                }
            };
            generate_regular_winternitz_tests!(
                &ps, public_key, message, message_checker, false;
                [0, 0, true],
                [0, 1, true],
                [1, 0, true],
                [1, 1, true],
                [2, 0, true],
                [2, 1, true]
            );
            generate_hybrid_winternitz_tests!(
                &ps, public_key, message, message_checker, false;
                [0, true],
                [1, true]
            );
        }
    }
}
