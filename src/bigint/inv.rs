use crate::bigint::BigIntImpl;
use crate::treepp::*;
use core::ops::{Mul, Rem, Sub};
use num_bigint::BigUint;
use num_traits::Num;

impl<const N_BITS: u32> BigIntImpl<N_BITS> {
    pub fn div2() -> Script {
        script! {
            { Self::div2rem() }
            OP_DROP
        }
    }

    pub fn div2rem() -> Script {
        script! {
            { Self::N_LIMBS - 1 } OP_ROLL
            0
            { u30_shr1_carry(Self::HEAD) }

            for _ in 1..Self::N_LIMBS {
                { Self::N_LIMBS } OP_ROLL
                OP_SWAP
                { u30_shr1_carry(30) }
            }
        }
    }

    pub fn div3() -> Script {
        script! {
            { Self::div3rem() }
            OP_DROP
        }
    }

    pub fn div3rem() -> Script {
        script! {
            { Self::N_LIMBS - 1 } OP_ROLL
            0
            { u30_div3_carry() }

            for _ in 1..Self::N_LIMBS {
                { Self::N_LIMBS } OP_ROLL
                OP_SWAP
                { u30_div3_carry() }
            }
        }
    }

    /// Input: a b
    ///  a is the modulus
    ///  b is the number
    ///
    /// The algorithm is from Constant Time Modular Inversion, Joppe W. Bos
    pub fn inv_stage1() -> Script {
        script! {
            { Self::push_u32_le(&[0]) }
            { Self::roll(1) }
            { Self::push_u32_le(&[1]) }
            { 0 }

            // The stack starts with
            //  u    N elements
            //  r    N elements
            //  v    N elements
            //  s    N elements
            //  k    1 element

            // send k to the altstack
            OP_TOALTSTACK

            // stack invariant for this loop: u, r, v, s | k
            for _ in 0..2 * Self::N_BITS {
                // copy u, v
                { Self::copy(3) }
                { Self::copy(2) }

                // check if u = v
                { Self::notequal(1, 0)}

                // if the algorithm has not terminated (u != v)
                OP_IF
                    // compute 2 * s
                    { Self::copy(0) }
                    { Self::double(0) }

                    // compute 2 * r
                    { Self::copy(3) }
                    { Self::double(0) }

                    // compute u/2
                    { Self::copy(5) }
                    { Self::div2rem() }
                    OP_NOT

                    // current stack: u, r, v, s, 2 * s, 2 * r, u/2

                    // case 1: u = 0 mod 2
                    OP_IF
                        // start stack: u, r, v, s, 2 * s, 2 * r, u/2 | k

                        // roll the r
                        { Self::roll(5) }

                        // roll the v
                        { Self::roll(5) }

                        // roll the 2 * s
                        { Self::roll(4) }

                        // remove the unused u
                        { Self::roll(6) }
                        { Self::drop() }

                        // remove the unused s
                        { Self::roll(5) }
                        { Self::drop() }

                        // remove the unused 2 * r
                        { Self::roll(4) }
                        { Self::drop() }

                        // final stack: u/2, r, v, 2 * s | k
                    OP_ELSE
                        // compute v/2
                        { Self::copy(4) }
                        { Self::div2rem() }
                        OP_NOT

                        // case 2: v = 0 mod 2
                        OP_IF
                            // start stack: u, r, v, s, 2 * s, 2 * r, u/2, v/2 | k

                            // roll the u
                            { Self::roll(7) }

                            // roll the 2 * r
                            { Self::roll(3) }

                            // roll the v/2
                            { Self::roll(2) }

                            // roll the s
                            { Self::roll(5) }

                            // remove the unused r
                            { Self::roll(7) }
                            { Self::drop() }

                            // remove the unused v
                            { Self::roll(6) }
                            { Self::drop() }

                            // remove the unused 2 * s
                            { Self::roll(5) }
                            { Self::drop() }

                            // remove the unused u/2
                            { Self::roll(4) }
                            { Self::drop() }

                            // final stack: u, 2 * r, v/2, s | k
                        OP_ELSE
                            // copy u, v
                            { Self::copy(7) }
                            { Self::copy(6) }

                            // compute u > v
                            { Self::greaterthan(1, 0) }
                            OP_TOALTSTACK

                            // reorder u/2 and v/2 if u < v
                            OP_FROMALTSTACK OP_DUP OP_TOALTSTACK
                            OP_NOT
                            OP_IF
                                { Self::roll(1) }
                            OP_ENDIF

                            // compute (u - v)/2 (if u > v) or (v - u)/2 (if v > u)
                            { Self::sub(1, 0) }

                            // compute r + s
                            { Self::roll(5) }
                            { Self::roll(4) }
                            { Self::add(1, 0) }

                            OP_FROMALTSTACK

                            // case 3: u > v
                            OP_IF
                                // start stack: u, v, 2 * s, 2 * r, (u/2 - v/2), r + s | k

                                // roll the v
                                { Self::roll(4) }

                                // roll the 2 * s
                                { Self::roll(4) }

                                // remove the unused u
                                { Self::roll(5) }
                                { Self::drop() }

                                // remove the unused 2 * r
                                { Self::roll(4) }
                                { Self::drop() }

                                // final stack: (u/2 - v/2), r + s, v, 2 * s | k
                            OP_ELSE
                                // start stack: u, v, 2 * s, 2 * r, (v/2 - u/2), r + s | k

                                // roll the u
                                { Self::roll(5) }

                                // roll the 2 * r
                                { Self::roll(3) }

                                // roll the (v/2 - u/2)
                                { Self::roll(3) }

                                // roll the r + s
                                { Self::roll(3) }

                                // remove the unused v
                                { Self::roll(5) }
                                { Self::drop() }

                                // remove the unused 2 * s
                                { Self::roll(4) }
                                { Self::drop() }

                                // final stack: u, 2 * r, (v/2 - u/2), r + s | k
                            OP_ENDIF
                        OP_ENDIF
                    OP_ENDIF

                    // increase k
                    OP_FROMALTSTACK
                    OP_1ADD
                    OP_TOALTSTACK
                OP_ENDIF
            }

            { Self::roll(1) }
            { Self::drop() }
            { Self::roll(1) }
            { Self::drop() }
            { Self::roll(1) }
            { Self::drop() }
            OP_FROMALTSTACK

            // final stack: s k
        }
    }

    pub fn inv_stage2(modulus_hex: &str) -> Script {
        let modulus = BigUint::from_str_radix(modulus_hex, 16).unwrap();

        let inv_2 = BigUint::from(2u8).modpow(&modulus.clone().sub(BigUint::from(2u8)), &modulus);
        let inv_2k = inv_2.modpow(&BigUint::from(Self::N_BITS), &modulus);

        let mut inv_list = vec![];
        let mut cur = inv_2k;
        for _ in 0..=Self::N_BITS {
            inv_list.push(cur.clone());
            cur = cur.mul(&inv_2).rem(&modulus);
        }

        script! {
            { Self::N_BITS } OP_SUB

            for i in 0..=Self::N_BITS {
                OP_DUP { i } OP_EQUAL OP_IF
                    { Self::push_u32_le(&inv_list[i as usize].to_u32_digits()) }
                    for _ in 0..Self::N_LIMBS {
                        OP_TOALTSTACK
                    }
                OP_ENDIF
            }

            OP_DROP

            for _ in 0..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }
}

pub fn u30_shr1_carry(num_bits: u32) -> Script {
    script! {
        2                           // 2^1
        for _ in 0..num_bits - 2 {
            OP_DUP OP_DUP OP_ADD
        }                           // 2^2 to 2^{num_bits - 1}
        { num_bits - 1 } OP_ROLL
        OP_IF
            OP_DUP
        OP_ELSE
            0
        OP_ENDIF
        OP_TOALTSTACK

        { num_bits - 1 } OP_ROLL

        for _ in 0..num_bits - 2 {
            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB OP_SWAP OP_DUP OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_SWAP
            OP_ELSE
                OP_NIP
            OP_ENDIF
        }

        OP_2DUP OP_LESSTHANOREQUAL
        OP_IF
            OP_SWAP OP_SUB OP_FROMALTSTACK OP_1ADD
        OP_ELSE
            OP_NIP OP_FROMALTSTACK
        OP_ENDIF
        OP_SWAP
    }
}

// divide u30 by 3, also remainder
pub fn u30_div3_carry() -> Script {
    let x = 357913941;
    let y = 715827882;
    let mut v = Vec::new();
    let k = 19; // ceil log_3 (2^30)
    for i in 0..19 {
        let a = 3_u32.pow(i);
        v.push(a);
        v.push(2 * a);
    }

    script! {
        for b in v {
            { b }
        }

        { 2 * k } OP_ROLL OP_DUP
        0 OP_GREATERTHAN
        OP_IF
            1 OP_SUB
            OP_IF
                2 { y }
            OP_ELSE
                1 { x }
            OP_ENDIF
        OP_ELSE
            OP_DROP 0 0
        OP_ENDIF
        OP_TOALTSTACK

        { 2 * k + 1 } OP_ROLL OP_ADD

        for _ in 0..2 * k - 2 {
            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB 2 OP_PICK OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
            OP_ELSE
                OP_NIP
            OP_ENDIF
        }

        OP_NIP OP_NIP OP_FROMALTSTACK OP_SWAP
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::inv::{u30_div3_carry, u30_shr1_carry};
    use crate::bigint::U254;
    use crate::treepp::*;
    use core::ops::{Div, Shr};
    use num_bigint::{BigUint, RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_u30_shr1_carry() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a = a % (1 << 30);

            let script = script! {
                { a }
                { 0 }
                { u30_shr1_carry(30) }
                { a & 1 } OP_EQUALVERIFY
                { a >> 1 } OP_EQUAL
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a = a % (1 << 30);

            let script = script! {
                { a }
                { 1 }
                { u30_shr1_carry(30) }
                { a & 1 } OP_EQUALVERIFY
                { (1 << 29) | (a >> 1) } OP_EQUAL
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_u30_div3_carry() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a = a % (1 << 30);
            let k = 2_u32.pow(30);

            for r in 0..3 {
                let a2 = a + r * k;
                let b = a2 % 3;
                let c = a2 / 3;
                let script = script! {
                    { a }
                    { r }
                    { u30_div3_carry() }
                    { b } OP_EQUALVERIFY
                    { c } OP_EQUAL
                };

                let exec_result = execute_script(script);
                assert!(exec_result.success);
            }
        }
    }

    #[test]
    fn test_div2() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = a.clone().shr(1);

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::div2() }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_div3() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = a.clone().div(BigUint::from(3_u32));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::div3() }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
