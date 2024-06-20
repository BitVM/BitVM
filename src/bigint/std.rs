use num_bigint::BigUint;
use num_traits::Num;
use std::str::FromStr;

use crate::bigint::BigIntImpl;
use crate::pseudo::push_to_stack;
use crate::treepp::*;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub fn push_u32_le(v: &[u32]) -> Script {
        let mut bits = vec![];
        for elem in v.iter() {
            for i in 0..32 {
                bits.push((elem & (1 << i)) != 0);
            }
        }
        bits.resize(N_BITS as usize, false);

        let mut limbs = vec![];
        for chunk in bits.chunks(LIMB_SIZE as usize) {
            let mut chunk_vec = chunk.to_vec();
            chunk_vec.resize(LIMB_SIZE as usize, false);

            let mut elem = 0u32;
            for i in 0..LIMB_SIZE as usize {
                if chunk_vec[i] {
                    elem += 1 << i;
                }
            }

            limbs.push(elem);
        }

        limbs.reverse();

        script! {
            for limb in &limbs {
                { *limb }
            }
            { push_to_stack(0,Self::N_LIMBS as usize - limbs.len()) }
        }
    }

    pub fn push_u64_le(v: &[u64]) -> Script {
        let v = v
            .iter()
            .flat_map(|v| {
                [
                    (v & 0xffffffffu64) as u32,
                    ((v >> 32) & 0xffffffffu64) as u32,
                ]
            })
            .collect::<Vec<u32>>();

        Self::push_u32_le(&v)
    }

    /// Zip the top two u{16N} elements
    /// input:  a0 ... a{N-1} b0 ... b{N-1}
    /// output: a0 b0 ... ... a{N-1} b{N-1}
    pub fn zip(mut a: u32, mut b: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;
        b = (b + 1) * Self::N_LIMBS - 1;

        assert_ne!(a, b);
        if a < b {
            script! {
                for i in 0..Self::N_LIMBS {
                    { a + i }
                    OP_ROLL
                    { b }
                    OP_ROLL
                }
            }
        } else {
            script! {
                for i in 0..Self::N_LIMBS {
                    { a }
                    OP_ROLL
                    { b + i + 1 }
                    OP_ROLL
                }
            }
        }
    }

    pub fn copy_zip(mut a: u32, mut b: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;
        b = (b + 1) * Self::N_LIMBS - 1;

        script! {
            for i in 0..Self::N_LIMBS {
                { a + i } OP_PICK { b + 1 + i } OP_PICK
            }
        }
    }

    pub fn dup_zip(mut a: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            for i in 0..Self::N_LIMBS {
                { a + i } OP_ROLL OP_DUP
            }
        }
    }

    pub fn copy(mut a: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            { a + 1 }
            for _ in 0..Self::N_LIMBS - 1 {
                OP_DUP OP_PICK OP_SWAP
            }
            OP_1SUB OP_PICK
        }
    }

    pub fn roll(mut a: u32) -> Script {
        if a == 0 {
            return script!{};
        }
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            for _ in 0..Self::N_LIMBS {
                { a } OP_ROLL
            }
        }
    }

    pub fn drop() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS / 2 {
                OP_2DROP
            }
            if Self::N_LIMBS & 1 == 1 {
                OP_DROP
            }
        }
    }

    pub fn push_dec(dec_string: &str) -> Script {
        Self::push_u32_le(&BigUint::from_str(dec_string).unwrap().to_u32_digits())
    }

    pub fn push_hex(hex_string: &str) -> Script {
        Self::push_u32_le(
            &BigUint::from_str_radix(hex_string, 16)
                .unwrap()
                .to_u32_digits(),
        )
    }

    #[inline]
    pub fn push_zero() -> Script { push_to_stack(0, Self::N_LIMBS as usize) }

    #[inline]
    pub fn push_one() -> Script {
        script! {
            { push_to_stack(0,(Self::N_LIMBS - 1) as usize) }
            1
        }
    }

    pub fn is_zero_keep_element(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for i in 0..Self::N_LIMBS {
                { a + i+1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_zero(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for _ in 0..Self::N_LIMBS {
                { a +1 } OP_ROLL
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_one_keep_element(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            { a + 1 } OP_PICK
            1 OP_EQUAL OP_BOOLAND
            for i in 1..Self::N_LIMBS {
                { a + i + 1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_one(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            { a + 1 } OP_ROLL
            1 OP_EQUAL OP_BOOLAND
            for _ in 1..Self::N_LIMBS {
                { a + 1 } OP_ROLL
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
                OP_TOALTSTACK
            }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::{BigIntImpl, U254};
    use crate::treepp::{execute_script, pushable};
    use bitcoin_script::script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_zip() {
        const N_BITS: u32 = 1450;
        const N_U30_LIMBS: u32 = 50;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[(N_U30_LIMBS + i) as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { BigIntImpl::<N_BITS, 29>::zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[(N_U30_LIMBS + i) as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { BigIntImpl::<N_BITS, 29>::zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_copy() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_roll() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::roll(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_copy_zip() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[(N_U30_LIMBS + i) as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[(N_U30_LIMBS + i) as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(1, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::dup_zip(1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn push_hex() {
        let exec_result = execute_script(script! {
            { U254::push_hex("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47") }
            { 0x187cfd47 } OP_EQUALVERIFY // 410844487
            { 0x10460b6 } OP_EQUALVERIFY // 813838427
            { 0x1c72a34f } OP_EQUALVERIFY // 119318739
            { 0x2d522d0 } OP_EQUALVERIFY // 542811226
            { 0x1585d978 } OP_EQUALVERIFY // 22568343
            { 0x2db40c0 } OP_EQUALVERIFY // 18274822
            { 0xa6e141 } OP_EQUALVERIFY // 436378501
            { 0xe5c2634 } OP_EQUALVERIFY // 329037900
            { 0x30644e } OP_EQUAL // 12388
        });
        assert!(exec_result.success);
    }
}
