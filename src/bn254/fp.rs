use crate::treepp::*;
use crate::bigint::{U254, MAX_U30};
use crate::bigint::add::{u30_add_carry};
use crate::bigint::sub::{u30_sub_carry};

type Bn254 = U254;

impl Bn254 {

    const MODULUS: &'static str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    pub fn push_modulus() -> Script {
        Self::push_hex(Self::MODULUS)
    }

    pub fn add_mod(a: u32, b: u32) -> Script {

        script! {
            { Self::zip(a, b) }

            { MAX_U30 }

            // A0 + B0
            u30_add_carry
            OP_SWAP
            OP_TOALTSTACK

            // from     A1      + B1        + carry_0
            //   to     A{N-2}  + B{N-2}    + carry_{N-3}
            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT
                OP_ADD
                OP_SWAP
                u30_add_carry
                OP_SWAP
                OP_TOALTSTACK
            }

            // A{N-1} + B{N-1} + carry_{N-2}
            OP_NIP
            OP_ADD
            OP_ADD

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }

            { Self::copy(0) }
            { Self::push_modulus() }
            { Self::greaterthanorequal(1, 0) }
            OP_IF
                { Self::push_modulus() }
                { Self::zip(1, 0) }

                { MAX_U30 }

                // A0 - B0
                u30_sub_carry
                OP_SWAP
                OP_TOALTSTACK

                // from     A1      - (B1        + borrow_0)
                //   to     A{N-2}  - (B{N-2}    + borrow_{N-3})
                for _ in 0..Self::N_LIMBS - 2 {
                    OP_ROT
                    OP_ADD
                    OP_SWAP
                    u30_sub_carry
                    OP_SWAP
                    OP_TOALTSTACK
                }

                // A{N-1} - (B{N-1} + borrow_{N-2})
                OP_NIP
                OP_ADD
                OP_SUB

                for _ in 0..Self::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            OP_ENDIF
        }
    }


    pub fn double_mod(a: u32) -> Script {
        script!{
            { Self::copy(a) }
            { Self::add_mod(a, 1) }
        }
    }

    pub fn mul_mod() -> Script {
        script! {
            { Self::convert_to_bits_toaltstack() }

            for _ in 0..Self::N_LIMBS {
                0
            }

            OP_FROMALTSTACK
            OP_IF
                { Self::copy(1) }
                { Self::add_mod(1, 0) }
            OP_ENDIF

            for _ in 1..Self::N_BITS - 1 {
                { Self::bring(1) }
                { Self::double_mod(0) }
                { Self::bring(1) }
                OP_FROMALTSTACK
                OP_IF
                    { Self::copy(1) }
                    { Self::add_mod(1, 0) }
                OP_ENDIF
            }

            { Self::bring(1) }
            { Self::double_mod(0) }
            OP_FROMALTSTACK
            OP_IF
                { Self::add_mod(1, 0) }
            OP_ELSE
                { Self::drop() }
            OP_ENDIF
        }
    }

}




#[cfg(test)]
mod test {
    use crate::treepp::*;
    use crate::bn254::fp::Bn254;
    use core::ops::{Add, Rem};
    use std::{ops::{Mul, Sub}};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::Num;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_add_mod() {
        let m = BigUint::from_str_radix(Bn254::MODULUS, 16).unwrap();
        
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        
        for _ in 0..100 {

            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(b.clone()).rem(&m);

            let script = script! {
                { Bn254::push_u32_le(&a.to_u32_digits()) }
                { Bn254::push_u32_le(&b.to_u32_digits()) }
                { Bn254::add_mod(1, 0) }
                { Bn254::push_u32_le(&c.to_u32_digits()) }
                { Bn254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double_mod() {
        let m = BigUint::from_str_radix(Bn254::MODULUS, 16).unwrap();

        for _ in 0..100 {

            let a: BigUint = m.clone().sub(BigUint::new(vec![1]));

            let a = a.rem(&m);
            let c: BigUint = a.clone().add(a.clone()).rem(&m);

            let script = script! {
                { Bn254::push_u32_le(&a.to_u32_digits()) }
                { Bn254::double_mod(0) }
                { Bn254::push_u32_le(&c.to_u32_digits()) }
                { Bn254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul_mod() {
        let m = BigUint::from_str_radix(Bn254::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..1 {

            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().mul(b.clone()).rem(&m);

            let script = script! {
                { Bn254::push_u32_le(&a.to_u32_digits()) }
                { Bn254::push_u32_le(&b.to_u32_digits()) }
                { Bn254::mul_mod() }
                { Bn254::push_u32_le(&c.to_u32_digits()) }
                { Bn254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
