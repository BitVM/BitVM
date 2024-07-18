use crate::bigint::BigIntImpl;
use crate::treepp::*;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    /// Double a BigInt
    pub fn double(a: u32) -> Script {
        if a == 0 {
            script! {
                OP_DUP
                OP_ADD
                { 1 << LIMB_SIZE }
                OP_SWAP

                limb_add_carry2
                OP_TOALTSTACK

                // from     A1      + B1        + carry_0
                //   to     A{N-2}  + B{N-2}    + carry_{N-3}
                for _ in 0..Self::N_LIMBS - 2 {
                    OP_ROT
                    OP_DUP
                    OP_ADD
                    limb_add_carry3 OP_TOALTSTACK
                }

                // A{N-1} + B{N-1} + carry_{N-2}
                OP_NIP
                OP_SWAP
                OP_DUP
                OP_ADD
                { limb_add_nocarry(Self::HEAD_OFFSET) }

                for _ in 0..Self::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            }
        } else {
            script! {
                { Self::dup_zip(a) }

                OP_ADD
                { 1 << LIMB_SIZE }
                OP_SWAP

                limb_add_carry2
                OP_TOALTSTACK

                // from     A1      + B1        + carry_0
                //   to     A{N-2}  + B{N-2}    + carry_{N-3}
                for _ in 0..Self::N_LIMBS - 2 {
                    OP_2SWAP
                    OP_ADD
                    limb_add_carry3 OP_TOALTSTACK
                }

                // A{N-1} + B{N-1} + carry_{N-2}
                OP_NIP
                OP_ADD
                { limb_add_nocarry(Self::HEAD_OFFSET) }

                for _ in 0..Self::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            }
        }
    }

    /// Compute the sum of two BigInts
    pub fn add(a: u32, b: u32) -> Script {
        if b == 0 {
            script! {
                {a * Self::N_LIMBS} OP_ROLL
                OP_ADD
    
                { 1 << LIMB_SIZE }
                OP_SWAP
    
                limb_add_carry2
                OP_TOALTSTACK
    
                // from     A1      + B1        + carry_0
                //   to     A{N-2}  + B{N-2}    + carry_{N-3}
                for i in 0..Self::N_LIMBS - 2 {
                    OP_ROT
                    {a * Self::N_LIMBS - i + 1} OP_ROLL
                    OP_ADD
                    limb_add_carry3 OP_TOALTSTACK
                }
    
                // A{N-1} + B{N-1} + carry_{N-2}
                OP_NIP
                {(a-1) * Self::N_LIMBS + 2} OP_ROLL
                OP_ADD
                { limb_add_nocarry(Self::HEAD_OFFSET) }
    
                for _ in 0..Self::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            }
        } else {
            script! {
                { Self::zip(a, b) }

                OP_ADD
                { 1 << LIMB_SIZE }
                OP_SWAP

                limb_add_carry2
                OP_TOALTSTACK

                // from     A1      + B1        + carry_0
                //   to     A{N-2}  + B{N-2}    + carry_{N-3}
                for _ in 0..Self::N_LIMBS - 2 {
                    OP_2SWAP
                    OP_ADD
                    limb_add_carry3 OP_TOALTSTACK
                }

                // A{N-1} + B{N-1} + carry_{N-2}
                OP_NIP
                OP_ADD
                { limb_add_nocarry(Self::HEAD_OFFSET) }

                for _ in 0..Self::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            }
        }
    }

    pub fn add1() -> Script {
        script! {
            OP_1ADD
            { 1 << LIMB_SIZE }
            OP_SWAP

            limb_add_carry2
            OP_TOALTSTACK

            // from     A1        + carry_0
            //   to     A{N-2}    + carry_{N-3}
            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT
                limb_add_carry3 OP_TOALTSTACK
            }

            // A{N-1} + carry_{N-2}
            OP_NIP
            { limb_add_nocarry(Self::HEAD_OFFSET) }

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }
}

/// Compute the sum of two limbs, including the carry bit
///
/// Optimized by: @stillsaiko
pub fn limb_add_carry() -> Script {
    script! {
        OP_ROT OP_ROT
        OP_ADD OP_2DUP
        OP_LESSTHANOREQUAL
        OP_TUCK
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}


pub fn limb_add_carry2() -> Script {
    script! {
        OP_2DUP
        OP_LESSTHANOREQUAL
        OP_TUCK
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

pub fn limb_add_carry3() -> Script {
    script! {
        OP_ADD OP_2DUP
        OP_LESSTHANOREQUAL
        OP_TUCK
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

pub fn limb_add_carry4() -> Script {
    script! {
        OP_ADD OP_2DUP
        OP_LESSTHANOREQUAL
        OP_TUCK
        OP_IF
            3 OP_PICK OP_SUB
        OP_ENDIF
    }
}

/// Compute the sum of two limbs, dropping the carry bit
///
/// Optimized by: @wz14
pub fn limb_add_nocarry(head_offset: u32) -> Script {
    script! {
        OP_ADD { head_offset } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
        OP_ELSE
            OP_DROP
        OP_ENDIF
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::{U254, U64};
    use crate::treepp::*;
    use core::ops::{Add, Rem, Shl};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_add() {
        println!("U254.add(1, 0): {} bytes", U254::add(1, 0).len());
        println!("U254.add(2, 0): {} bytes", U254::add(2, 0).len());
        println!("U254.add(2, 1): {} bytes", U254::add(2, 1).len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone() + b.clone()).rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::add(1, 0) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::add(2, 0) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::add(2, 1) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u64 = prng.gen();
            let b: u64 = prng.gen();
            let c = a.wrapping_add(b);

            let script = script! {
                { U64::push_u64_le(&[a]) }
                { U64::push_u64_le(&[b]) }
                { U64::add(1, 0) }
                { U64::push_u64_le(&[c]) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double() {
        println!("U254.double(0): {} bytes", U254::double(0).len());
        println!("U254.double(1): {} bytes", U254::double(1).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone() + a.clone()).rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::double(0) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_zero() }
                { U254::double(1) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u64 = prng.gen();
            let c = a.wrapping_add(a);

            let script = script! {
                { U64::push_u64_le(&[a]) }
                { U64::double(0) }
                { U64::push_u64_le(&[c]) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_1add() {
        println!("U254.add1: {} bytes", U254::add1().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone().add(BigUint::one())).rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::add1() }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: u64 = prng.gen();
            let c = a.wrapping_add(1u64);

            let script = script! {
                { U64::push_u64_le(&[a]) }
                { U64::add1() }
                { U64::push_u64_le(&[c]) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
