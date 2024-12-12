use super::utils::*;
use crate::treepp::*;
use bitcoin::{
    hashes::{hash160, Hash},
    Witness,
};
use serde::{Deserialize, Serialize};
use std::{cmp::min, marker::PhantomData};

type HashOut = [u8; 20];
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct Parameters {
    n0: u32,
    log_d: u32,
    n1: u32,
    d: u32,
    n: u32,
}

pub struct DigitSignature {
    pub hash_bytes: Vec<u8>,
    pub message_digit: u32,
}

impl Parameters {
    pub const fn new(n0: u32, log_d: u32) -> Self {
        assert!(
            4 <= log_d && log_d <= 8,
            "You can only choose block lengths in the range [4, 8]"
        );
        let d: u32 = (1 << log_d) - 1;
        let n1: u32 = log_base_ceil(d * n0, d + 1) + 1;
        let n: u32 = n0 + n1;
        Parameters {
            n0,
            log_d,
            n1,
            d,
            n,
        }
    }
    fn byte_message_length(&self) -> u32 { (self.n0 * self.log_d + 7) / 8}
    pub fn total_digit_count(&self) -> u32 { self.n }
}

fn public_key_for_digit(ps: &Parameters, secret_key: &SecretKey, digit_index: u32) -> HashOut {
    let mut secret_i = secret_key.clone();
    secret_i.push(digit_index as u8);
    let mut hash = hash160::Hash::hash(&secret_i);
    for _ in 0..ps.d {
        hash = hash160::Hash::hash(&hash[..]);
    }
    *hash.as_byte_array()
}

pub fn digit_signature(
    secret_key: &SecretKey,
    digit_index: u32,
    message_digit: u32,
) -> DigitSignature {
    let mut secret_i = secret_key.clone();
    secret_i.push(digit_index as u8);
    let mut hash = hash160::Hash::hash(&secret_i);
    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }
    let hash_bytes = hash.as_byte_array().to_vec();
    DigitSignature {
        hash_bytes,
        message_digit,
    }
}

pub fn generate_public_key(ps: &Parameters, secret_key: &SecretKey) -> PublicKey {
    let mut public_key = PublicKey::new();
    public_key.reserve(ps.n as usize);
    for i in 0..ps.n {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

fn checksum(ps: &Parameters, digits: Vec<u32>) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit;
    }
    ps.d * ps.n0 - sum
}

fn add_message_checksum(ps: &Parameters, mut digits: Vec<u32>) -> Vec<u32> {
    let mut checksum_digits = to_digits(checksum(ps, digits.clone()), ps.d + 1, ps.n1 as i32);
    checksum_digits.append(&mut digits);
    checksum_digits.reverse();
    checksum_digits
}
/*
    VERIFIER: These are signature verifiers
        1)  ListpickVerifier:
            Description: This generates hashes for each possible value and then uses OP_PICK
            to get the corresponding one from the created list. Also as a small improvement, it
            divides the length of the list by 2 in the start

            Signature format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0 (With digits)

            Approximate Max Stack Depth: 2N + D/2

        2)  BruteforceVerifier:
            Description: This tries each possible value straightforwardly

            Signature format: hash_{n - 1}, hash_{n - 2} ... hash_0 (Without digits)

            Approximate Max Stack Depth: N

        3)  BinarysearchVerifier:
            Description: This simulates a for loop of hashing using binary search on the digit

            Signature format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0 (With digits)

            Approximate Max Stack Depth: 2N

        4)  HybridVerifier:
            Descripton: This narrows the search space first by doing binary search, then uses a list for the remaning space
            i.e. it uses Algorithm 3 and Algorithm 1 consequently

            Signature format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0 (With digits)

            Approximate Max Stack Depth: 2N + REMAINING_SPACE_SIZE

    CONVERTER: These are digits to bytes converters
        1)  TabledConverter:
            Descripton: This uses a table for the divison of 2

            Approximate Max Stack Depth: N + D

        2)  StraightforwardConverter:
            Descripton: This just uses OP_IF's to decompose the numbers into bits

            Approximate Max Stack Depth: N

    Sample Usage:
        Pick the algorithms you want to use, i.e. BinarysearchVerifier and StraightforwardConverter
        Construct your struct: let o = Winternitz::<BinarysearchVerifier, StraightforwardConverter>::new();
        Choose your n0 and log_d values for the calculation of other variables: let p = Parameters::new(n0, log_d);
        Use the methods for the necessary operations, for example: o.sign(&p, ...), o.checksig_verify(&p, ...)
*/

pub trait Verifier {
    // Default digit signatures
    fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: Vec<u32>) -> Witness {
        let digits = add_message_checksum(ps, digits);
        let mut result = Witness::new();
        for i in 0..ps.n {
            let sig = digit_signature(secret_key, i, digits[i as usize]);
            result.push(sig.hash_bytes);
            result.push(u32_to_le_bytes_minimal(digits[i as usize]));
        }
        result
    }
}
pub trait Converter {
    fn get_script(ps: &Parameters) -> Script;
}
pub struct Winternitz<VERIFIER: Verifier, CONVERTER: Converter> {
    phantom0: PhantomData<VERIFIER>,
    phantom1: PhantomData<CONVERTER>,
}

impl<VERIFIER: Verifier, CONVERTER: Converter> Default for Winternitz<VERIFIER, CONVERTER> {
    fn default() -> Self {
        Self::new()
    }
}

impl<VERIFIER: Verifier, CONVERTER: Converter> Winternitz<VERIFIER, CONVERTER> {
    pub const fn new() -> Self {
        Winternitz {
            phantom0: PhantomData,
            phantom1: PhantomData,
        }
    }

    pub fn sign_digits(
        &self,
        ps: &Parameters,
        secret_key: &SecretKey,
        digits: Vec<u32>,
    ) -> Witness {
        VERIFIER::sign_digits(ps, secret_key, digits)
    }

    pub fn sign(
        &self,
        ps: &Parameters,
        secret_key: &SecretKey,
        message_bytes: &Vec<u8>,
    ) -> Witness {
        VERIFIER::sign_digits(
            ps,
            secret_key,
            bytes_to_u32s(ps.n0, ps.log_d, message_bytes),
        )
    }

    fn verify_checksum(&self, ps: &Parameters) -> Script {
        script! {
            OP_FROMALTSTACK OP_DUP OP_NEGATE
            for _ in 1..ps.n0 {
                OP_FROMALTSTACK OP_TUCK OP_SUB
            }
            { ps.d * ps.n0 }
            OP_ADD
            OP_FROMALTSTACK
            for _ in 0..ps.n1 - 1 {
                for _ in 0..ps.log_d {
                    OP_DUP OP_ADD
                }
                OP_FROMALTSTACK
                OP_ADD
            }
            OP_EQUALVERIFY
        }
    }
}

pub struct ListpickVerifier {}
impl Verifier for ListpickVerifier {}

impl<CONVERTER: Converter> Winternitz<ListpickVerifier, CONVERTER> {
    fn verify_digits(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            for digit_index in 0..ps.n {
                // See https://github.com/BitVM/BitVM/issues/35
                { ps.d }
                OP_MIN
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

    pub fn checksig_verify(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
        let mut script = self.verify_digits(ps, public_key);
        script = script.push_script(self.verify_checksum(ps).compile());
        script.push_script(CONVERTER::get_script(ps).compile())
    }
}

pub struct BruteforceVerifier {}
impl Verifier for BruteforceVerifier {
    fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: Vec<u32>) -> Witness {
        let digits = add_message_checksum(ps, digits);
        let mut result = Witness::new();
        for i in 0..ps.n {
            let sig = digit_signature(secret_key, i, digits[i as usize]);
            result.push(sig.hash_bytes);
        }
        result
    }
}

impl<CONVERTER: Converter> Winternitz<BruteforceVerifier, CONVERTER> {
    fn verify_digits(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
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

    pub fn checksig_verify(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
        let mut script = self.verify_digits(ps, public_key);
        script = script.push_script(self.verify_checksum(ps).compile());
        script.push_script(CONVERTER::get_script(ps).compile())
    }
}

pub struct BinarysearchVerifier {}
impl Verifier for BinarysearchVerifier {}

impl<CONVERTER: Converter> Winternitz<BinarysearchVerifier, CONVERTER> {
    fn verify_digits(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            for digit_index in 0..ps.n {
                //one can send digits out of the range, i.e. negative or bigger than D for it to act as in range, so inorder for checksum to not be decreased, a lower bound check is necessary and enough
                OP_0
                OP_MAX
                OP_DUP
                OP_TOALTSTACK
                {ps.d} OP_SWAP OP_SUB
                for bit in (0..ps.log_d).rev() {
                    if bit != 0 {
                        {1 << bit}
                        OP_2DUP
                        OP_GREATERTHANOREQUAL
                        OP_IF
                            OP_SUB
                            OP_SWAP
                            for _ in 0..(1<<bit) {
                                OP_HASH160
                            }
                            OP_SWAP
                            OP_DUP
                        OP_ENDIF
                        OP_DROP
                    } else {
                        OP_IF
                            OP_HASH160
                        OP_ENDIF
                    }
                }
                { (public_key[(ps.n - 1 - digit_index) as usize]).to_vec() }
                OP_EQUALVERIFY
            }
        }
    }

    pub fn checksig_verify(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
        let mut script = self.verify_digits(ps, public_key);
        script = script.push_script(self.verify_checksum(ps).compile());
        script.push_script(CONVERTER::get_script(ps).compile())
    }
}

pub struct HybridVerifier {}
impl Verifier for HybridVerifier {}

impl<CONVERTER: Converter> Winternitz<HybridVerifier, CONVERTER> {
    fn verify_digits(&self, ps: &Parameters, public_key: &PublicKey, block_log_d: u32) -> Script {
        let block_d = (1 << block_log_d) - 1;
        script! {
            for digit_index in 0..ps.n {
                { ps.d }
                OP_MIN
                OP_DUP
                OP_TOALTSTACK
                {ps.d} OP_SWAP OP_SUB
                for bit in (block_log_d..ps.log_d).rev() {
                    {1 << bit}
                    OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB
                        OP_SWAP
                        for _ in 0..(1<<bit) {
                            OP_HASH160
                        }
                        OP_SWAP
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

    pub fn checksig_verify(
        &self,
        ps: &Parameters,
        public_key: &PublicKey,
        block_log_d: u32,
    ) -> Script {
        assert!((1..ps.log_d).contains(&block_log_d));
        let mut script = self.verify_digits(ps, public_key, block_log_d);
        script = script.push_script(self.verify_checksum(ps).compile());
        script.push_script(CONVERTER::get_script(ps).compile())
    }
}

pub struct TabledConverter {}
impl Converter for TabledConverter {
    fn get_script(ps: &Parameters) -> Script {
        let mut turning_into_bytes;
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
                if ps.n0 > 1 {
                    for _ in 0..ps.n0 / 2 - 1{
                        OP_FROMALTSTACK
                    }
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
            script_lines.push(script! {
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
}

pub struct StraightforwardConverter {}
impl Converter for StraightforwardConverter {
    fn get_script(ps: &Parameters) -> Script {
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
                    if i != (ps.n0/2) - 1 {
                        OP_TOALTSTACK
                    }
                }
                if ps.n0 > 1 {
                    for _ in 0..ps.n0 / 2 - 1{
                        OP_FROMALTSTACK
                    }
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
            let mut last_bytes = (8 - (ps.n0 * ps.log_d % 8)) % 8;
            let mut is_last_zero = true;
            script_lines.push(script! {
                OP_0
            });
            for i in 0..lens.len() {
                let l = lens[i];
                if last_bytes >= 8 {
                    //assert!(last_bytes == 8);
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
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::sync::Mutex;
    lazy_static::lazy_static! {
        static ref MALICIOUS_RNG: Mutex<ChaCha20Rng> = Mutex::new(ChaCha20Rng::seed_from_u64(337));
    }

    const SAMPLE_SECRET_KEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
    const TEST_COUNT: u32 = 20;

    //This test is not extensive and definitely misses corner cases, if there are any
    fn try_malicious(ps: &Parameters, _message: &Vec<u8>, verifier: &str) -> Script {
        let mut rng = MALICIOUS_RNG.lock().unwrap();
        let ind = rng.gen_range(0..ps.n);
        if verifier == get_type_name::<BruteforceVerifier>() {
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
            if $desired_outcome == true {
                assert!(
                    execute_script($s.push_script($message_checker.clone().compile())).success
                        == true
                );
            } else {
                assert!(
                    execute_script($s.clone()).success == false
                        || execute_script($s.push_script($message_checker.clone().compile()))
                            .success
                            == true
                );
            }
        };
    }
    macro_rules! generate_regular_winternitz_tests {
        (
            $ps:expr, $secret_key:expr, $public_key:expr, $message:expr, $message_checker:expr, $desired_outcome:expr;
            $([$verifier:ty, $converter:ty]),*
        ) => {
            $(
                {
                    let o = Winternitz::<$verifier, $converter>::new();
                    let s = script! {
                        { o.sign(&$ps, &$secret_key, &$message) }
                        if $desired_outcome == false {
                             { try_malicious(&$ps, &$message, &get_type_name::<$verifier>()) }
                        }
                        { o.checksig_verify(&$ps, &$public_key) }
                    };

                    println!("For N0:{} and LOG_D:{}  {} with {} =>", $ps.n0, $ps.log_d, get_type_name::<$verifier>(), get_type_name::<$converter>());
                    test_script!($ps, s, $message_checker, $desired_outcome);
                }
            )*
        };
    }
    macro_rules! generate_hybrid_winternitz_tests {
        (
            $ps:expr, $secret_key:expr, $public_key:expr, $message:expr, $message_checker:expr, $desired_outcome:expr;
            $([$converter:ty]),*
        ) => {
            $(
                {
                    let o = Winternitz::<HybridVerifier, $converter>::new();
                    for i in 1..$ps.log_d {
                        let s = script! {
                            { o.sign(&$ps, &$secret_key, &$message) }
                            if $desired_outcome == false {
                                { try_malicious(&$ps, &$message, &get_type_name::<HybridVerifier>()) }
                           }
                            { o.checksig_verify(&$ps, &$public_key, i) }
                        };
                        println!("For N0:{} and LOG_D:{}  {} with {} block_log_d:{} =>", $ps.n0, $ps.log_d, get_type_name::<HybridVerifier>(), get_type_name::<$converter>(), i);
                        test_script!($ps, s, $message_checker, $desired_outcome);
                    }
                }
            )*
        };
    }

    #[test]
    fn test_winternitz_success() {
        let secret_key = match hex::decode(SAMPLE_SECRET_KEY) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
        let mut prng = ChaCha20Rng::seed_from_u64(37);
        for _ in 0..TEST_COUNT {
            let ps = Parameters::new(prng.gen_range(1..200), prng.gen_range(4..=8));
            let message_byte_size = ps.n0 * ps.log_d / 8;
            let mut message = vec![0u8; message_byte_size as usize];
            let mut return_message = vec![0; ps.byte_message_length() as usize];
            for i in 0..message_byte_size {
                message[i as usize] = prng.gen_range(0u8..=255);
                return_message[i as usize] = message[i as usize];
            }
            let public_key = generate_public_key(&ps, &secret_key);
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
                ps, secret_key, public_key, message, message_checker, true;
                [ListpickVerifier, TabledConverter],
                [ListpickVerifier, StraightforwardConverter],
                [BruteforceVerifier, TabledConverter],
                [BruteforceVerifier, StraightforwardConverter],
                [BinarysearchVerifier, TabledConverter],
                [BinarysearchVerifier, StraightforwardConverter]
            );
            generate_hybrid_winternitz_tests!(
                ps, secret_key, public_key, message, message_checker, true;
                [TabledConverter],
                [StraightforwardConverter]
            );
        }
    }

    #[test]
    fn test_winternitz_fail() {
        let secret_key = match hex::decode(SAMPLE_SECRET_KEY) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
        let mut prng = ChaCha20Rng::seed_from_u64(37);
        for _ in 0..TEST_COUNT {
            let ps = Parameters::new(prng.gen_range(1..200), prng.gen_range(4..=8));
            let message_byte_size = ps.n0 * ps.log_d / 8;
            let mut message = vec![0u8; message_byte_size as usize];
            let mut return_message = vec![0; ps.byte_message_length() as usize];
            for i in 0..message_byte_size {
                message[i as usize] = prng.gen_range(0u8..=255);
                return_message[i as usize] = message[i as usize];
            }
            let public_key = generate_public_key(&ps, &secret_key);
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
                ps, secret_key, public_key, message, message_checker, false;
                [ListpickVerifier, TabledConverter],
                [ListpickVerifier, StraightforwardConverter],
                [BruteforceVerifier, TabledConverter],
                [BruteforceVerifier, StraightforwardConverter],
                [BinarysearchVerifier, TabledConverter],
                [BinarysearchVerifier, StraightforwardConverter]
            );
            generate_hybrid_winternitz_tests!(
                ps, secret_key, public_key, message, message_checker, false;
                [TabledConverter],
                [StraightforwardConverter]
            );
        }
    }
}
