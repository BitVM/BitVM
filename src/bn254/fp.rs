use crate::bigint::add::u30_add_carry;
use crate::bigint::sub::u30_sub_carry;
use crate::bigint::{MAX_U30, U254};
use crate::treepp::*;

pub type Fp = U254;

impl Fp {
    const MODULUS: &'static str =
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    pub fn push_modulus() -> Script { Fp::push_hex(Fp::MODULUS) }

    pub fn push_zero() -> Script {
        script! {
            for _ in 0..Fp::N_LIMBS {
                0
            }
        }
    }

    pub fn push_one() -> Script {
        script! {
            for _ in 0..Fp::N_LIMBS - 1 {
                0
            }
            1
        }
    }

    pub fn add_mod(a: u32, b: u32) -> Script {
        script! {
            { Fp::zip(a, b) }

            { MAX_U30 }

            // A0 + B0
            u30_add_carry OP_TOALTSTACK

            // from     A1      + B1        + carry_0
            //   to     A{N-2}  + B{N-2}    + carry_{N-3}
            for _ in 0..Fp::N_LIMBS - 2 {
                OP_ROT
                OP_ADD
                OP_SWAP
                u30_add_carry OP_TOALTSTACK
            }

            // A{N-1} + B{N-1} + carry_{N-2}
            OP_NIP
            OP_ADD
            OP_ADD

            for _ in 0..Fp::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }

            { Fp::copy(0) }
            { Fp::push_modulus() }
            { Fp::greaterthanorequal(1, 0) }
            OP_IF
                { Fp::push_modulus() }
                { Fp::zip(1, 0) }

                { MAX_U30 }

                // A0 - B0
                u30_sub_carry
                OP_TOALTSTACK

                // from     A1      - (B1        + borrow_0)
                //   to     A{N-2}  - (B{N-2}    + borrow_{N-3})
                for _ in 0..Fp::N_LIMBS - 2 {
                    OP_ROT
                    OP_ADD
                    OP_SWAP
                    u30_sub_carry
                    OP_TOALTSTACK
                }

                // A{N-1} - (B{N-1} + borrow_{N-2})
                OP_NIP
                OP_ADD
                OP_SUB

                for _ in 0..Fp::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            OP_ENDIF
        }
    }

    pub fn neg_mod(a: u32) -> Script {
        script! {
            { Fp::push_modulus() }
            { Fp::sub(0, a + 1) }
        }
    }

    pub fn sub_mod(a: u32, b: u32) -> Script {
        script! {
            { Fp::neg_mod(b) }
            if a > b {
                { Fp::add_mod(0, a) }
            } else {
                { Fp::add_mod(0, a + 1) }
            }
        }
    }

    pub fn double_mod(a: u32) -> Script {
        script! {
            { Fp::copy(a) }
            { Fp::add_mod(a + 1, 0) }
        }
    }

    pub fn mul_mod() -> Script {
        script! {
            { Fp::convert_to_bits_toaltstack() }

            { Fp::push_zero() }

            OP_FROMALTSTACK
            OP_IF
                { Fp::copy(1) }
                { Fp::add_mod(1, 0) }
            OP_ENDIF

            for _ in 1..Fp::N_BITS - 1 {
                { Fp::roll(1) }
                { Fp::double_mod(0) }
                { Fp::roll(1) }
                OP_FROMALTSTACK
                OP_IF
                    { Fp::copy(1) }
                    { Fp::add_mod(1, 0) }
                OP_ENDIF
            }

            { Fp::roll(1) }
            { Fp::double_mod(0) }
            OP_FROMALTSTACK
            OP_IF
                { Fp::add_mod(1, 0) }
            OP_ELSE
                { Fp::drop() }
            OP_ENDIF
        }
    }

    pub fn square_mod() -> Script {
        script! {
            { Fp::copy(0) }
            { Fp::mul_mod() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::treepp::*;
    use core::ops::{Add, Rem};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::Num;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::ops::{Mul, Sub};

    #[test]
    fn test_add_mod() {
        println!("Fp.add: {} bytes", Fp::add_mod(0, 1).len());

        let m = BigUint::from_str_radix(Fp::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(b.clone()).rem(&m);

            let script = script! {
                { Fp::push_u32_le(&a.to_u32_digits()) }
                { Fp::push_u32_le(&b.to_u32_digits()) }
                { Fp::add_mod(1, 0) }
                { Fp::push_u32_le(&c.to_u32_digits()) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_sub_mod() {
        println!("Fp.sub: {} bytes", Fp::sub_mod(0, 1).len());

        let m = BigUint::from_str_radix(Fp::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(&m).sub(b.clone()).rem(&m);

            let script = script! {
                { Fp::push_u32_le(&a.to_u32_digits()) }
                { Fp::push_u32_le(&b.to_u32_digits()) }
                { Fp::sub_mod(1, 0) }
                { Fp::push_u32_le(&c.to_u32_digits()) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double_mod() {
        println!("Fp.double: {} bytes", Fp::double_mod(0).len());
        let m = BigUint::from_str_radix(Fp::MODULUS, 16).unwrap();

        for _ in 0..100 {
            let a: BigUint = m.clone().sub(BigUint::new(vec![1]));

            let a = a.rem(&m);
            let c: BigUint = a.clone().add(a.clone()).rem(&m);

            let script = script! {
                { Fp::push_u32_le(&a.to_u32_digits()) }
                { Fp::double_mod(0) }
                { Fp::push_u32_le(&c.to_u32_digits()) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul_mod() {
        println!("Fp.mul: {} bytes", Fp::mul_mod().len());
        let m = BigUint::from_str_radix(Fp::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().mul(b.clone()).rem(&m);

            let script = script! {
                { Fp::push_u32_le(&a.to_u32_digits()) }
                { Fp::push_u32_le(&b.to_u32_digits()) }
                { Fp::mul_mod() }
                { Fp::push_u32_le(&c.to_u32_digits()) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_square_mod() {
        println!("Fp.square: {} bytes", Fp::square_mod().len());
        let m = BigUint::from_str_radix(Fp::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let c: BigUint = a.clone().mul(a.clone()).rem(&m);

            let script = script! {
                { Fp::push_u32_le(&a.to_u32_digits()) }
                { Fp::square_mod() }
                { Fp::push_u32_le(&c.to_u32_digits()) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_neg_mod() {
        println!("Fp.neg: {} bytes", Fp::neg_mod(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let script = script! {
                { Fp::push_u32_le(&a.to_u32_digits()) }
                { Fp::copy(0) }
                { Fp::neg_mod(0) }
                { Fp::add_mod(0, 1) }
                { Fp::push_zero() }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
