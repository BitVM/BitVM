use crate::bn254::fp254impl::Fp254Impl;
use crate::bigint::U254;

use core::ops::Sub;

use crate::pseudo::OP_NDUP;
pub struct Fr;

impl Fp254Impl for Fr {
    const MODULUS: &'static str =
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    const MODULUS_LIMBS: [u32; Self::N_LIMBS as usize] = [
        // 0x30000001, 0x0F87D64F, 0x1B970914, 0x0CFA121E, 0x01585D28, 0x0116DA06, 0x1A029B85,
        // 0x139CB84C, 0x3064,
        0x10000001, 0x1f0fac9f, 0xe5c2450, 0x7d090f3, 0x1585d283, 0x2db40c0, 0xa6e141, 0xe5c2634, 0x30644e
    ];

    const P_PLUS_ONE_DIV2: &'static str =
        "183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001";

    const TWO_P_PLUS_ONE_DIV3: &'static str =
        "2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001";

    const P_PLUS_TWO_DIV3: &'static str =
        "10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a73150000001";
    type ConstantType = ark_bn254::Fr;

    fn mul() -> Script {
        script! {
            { fr_mul_montgomery(1, 0) }
        }
    }

    fn inv_montgomery() -> Script {
        script! {
            // 0x1baa96fcfe59ed6d917ad60144d1496b29b4a83e23e89803bafa616c601fddb2
            { 0x1baa96 }
            { 0x1f9fcb3d }
            { 0x15b645eb }
            { 0xb00a268 }
            { 0x1496b29b }
            { 0x9507c47 }
            { 0x1a2600ee }
            { 0x17d30b63 }
            { 0x1fddb2 }
            { Self::mul() }
        }
    }

    fn push_one() -> Script {
        script! {
            { 0xdc836 }
            { 0x52ac7a8 }
            { 0x11d54c07 }
            { 0x1d4240ce }
            { 0xaa8075b }
            { 0x17504f49 }
            { 0x52c068b }
            { 0x1ea70ab4 }
            { 0xfffff57 }
        }
    }

}

use num_bigint::BigUint;
use num_traits::Num;
use std::ops::Mul;
use std::ops::Rem;

impl Fr {
    pub fn push_fr_montgomery(v: &[u32]) -> Script {
        let r = BigUint::from_str_radix("dc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57", 16).unwrap();
        let p = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();
        script! {
            { Fr::push_u32_le(&BigUint::from_slice(v).mul(r).rem(p).to_u32_digits()) }
        }
    }
}

// p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
const FR_P: [u32; 9] = [
    0x10000001, 0x1f0fac9f, 0xe5c2450, 0x7d090f3, 0x1585d283, 0x2db40c0, 0xa6e141, 0xe5c2634, 0x30644e
];
// 2²⁶¹ mod p  <=>  0xdc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57
const FR_R: [u32; 9] = [
    0xfffff57, 0x1ea70ab4, 0x52c068b, 0x17504f49, 0xaa8075b, 0x1d4240ce, 0x11d54c07, 0x52ac7a8, 0xdc836
];
// inv₂₆₁ p  <=>  0xd8c07d0e2f27cbe4d1c6567d766f9dc6e9a7979b4b396ee4c3d1e0a6c10000001
const FR_P_INV_261: [u32; 9] = [
    0x10000001, 0x8f05360, 0x5bb930f, 0x12f36967, 0x1dc6e9a7, 0x13ebb37c, 0x19347195, 0x1c5e4f97, 0xd8c07d0
];

use crate::bigint::u29x9::{u29x9_mul_karazuba, u29x9_mullo_karazuba};
use crate::treepp::*;

pub fn fr_mul_montgomery(a: u32, b: u32) -> Script {
    script! {
        // a b
        { u29x9_mul_karazuba(a, b) }
        // hi lo
        for i in 0..9 {
            { FR_P_INV_261[8 - i] }
        }
        // hi lo p⁻¹
        { u29x9_mullo_karazuba(1, 0) }
        // hi lo*p⁻¹
        for i in 0..9 {
            { FR_P[8 - i] }
        }
        // hi lo*p⁻¹ p
        { u29x9_mul_karazuba(1, 0) }
        for _ in 0..9 {
            OP_DROP
        }
        // hi lo*p⁻¹*p
        for _ in 0..9 {
            OP_16 OP_1ADD OP_ROLL
        }
        // lo*p⁻¹*p hi

        { FR_P[0] } OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FR_P[1] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FR_P[2] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FR_P[3] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FR_P[4] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FR_P[5] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FR_P[6] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FR_P[7] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FR_P[8] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB /*OP_1*/ OP_ELSE OP_DROP /*OP_0*/ OP_ENDIF
        /*OP_SWAP*/ OP_TOALTSTACK

        for _ in 0..9 { OP_FROMALTSTACK }

        // lo*p⁻¹*p hi+p

        for _ in 0..9 {
            OP_16 OP_1ADD OP_ROLL
        }

        // hi+p lo*p⁻¹*p

        { Fr::zip(1, 0) }

        OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD OP_1 OP_ELSE OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        OP_ADD OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD OP_1 OP_ELSE OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        OP_ADD OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD OP_1 OP_ELSE OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        OP_ADD OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD OP_1 OP_ELSE OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        OP_ADD OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD OP_1 OP_ELSE OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        OP_ADD OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD OP_1 OP_ELSE OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        OP_ADD OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD OP_1 OP_ELSE OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        OP_ADD OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD OP_1 OP_ELSE OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        OP_ADD OP_SUB OP_DUP OP_0 OP_LESSTHAN
        OP_IF { 1 << 29 } OP_ADD /*OP_1 OP_ELSE OP_0*/ OP_ENDIF
        /*OP_SWAP*/ OP_TOALTSTACK

        for _ in 0..9 { OP_FROMALTSTACK }

        // hi+p-lo*p⁻¹*p
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_std::UniformRand;
    use core::ops::{Add, Mul, Rem, Sub};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::Num;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_add() {
        println!("Fr.add: {} bytes", Fr::add(0, 1).len());

        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(b.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::push_u32_le(&b.to_u32_digits()) }
                { Fr::add(1, 0) }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_sub() {
        println!("Fr.sub: {} bytes", Fr::sub(0, 1).len());

        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(&m).sub(b.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::push_u32_le(&b.to_u32_digits()) }
                { Fr::sub(1, 0) }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double() {
        println!("Fr.double: {} bytes", Fr::double(0).len());
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        for _ in 0..100 {
            let a: BigUint = m.clone().sub(BigUint::new(vec![1]));

            let a = a.rem(&m);
            let c: BigUint = a.clone().add(a.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::double(0) }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul() {
        println!("Fr.mul: {} bytes", Fr::mul().len());
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().mul(b.clone()).rem(&m);

            let script = script! {
                { Fr::push_fr_montgomery(&a.to_u32_digits()) }
                { Fr::push_fr_montgomery(&b.to_u32_digits()) }
                { Fr::mul() }
                { Fr::push_fr_montgomery(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_square() {
        println!("Fr.square: {} bytes", Fr::square().len());
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let c: BigUint = a.clone().mul(a.clone()).rem(&m);

            let script = script! {
                { Fr::push_fr_montgomery(&a.to_u32_digits()) }
                { Fr::square() }
                { Fr::push_fr_montgomery(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_neg() {
        println!("Fr.neg: {} bytes", Fr::neg(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::copy(0) }
                { Fr::neg(0) }
                { Fr::add(0, 1) }
                { Fr::push_zero() }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_inv() {
        println!("Fr.inv: {} bytes", Fr::inv().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fr::rand(&mut prng);
            let c = a.inverse().unwrap();

            let script = script! {
                { Fr::push_fr_montgomery(&BigUint::from(a).to_u32_digits()) }
                { Fr::inv() }
                { Fr::push_fr_montgomery(&BigUint::from(c).to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_div2() {
        println!("Fr.div2: {} bytes", Fr::div2().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fr::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fr::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fr::div2() }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_div3() {
        println!("Fr.div3: {} bytes", Fr::div3().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fr::rand(&mut prng);
            let b = a.clone().double();
            let c = a.add(b);

            let script = script! {
                { Fr::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fr::div3() }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_is_zero() {
        println!(
            "Fr.is_zero_keep_element: {} bytes",
            Fr::is_zero_keep_element(0).len()
        );
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fr::rand(&mut prng);

            let script = script! {
                // Push three Fr elements
                { Fr::push_zero() }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }

                // The first element should not be zero
                { Fr::is_zero_keep_element(0) }
                OP_NOT
                OP_TOALTSTACK

                // The third element should be zero
                { Fr::is_zero_keep_element(2) }
                OP_TOALTSTACK

                // Drop all three elements
                { Fr::drop() }
                { Fr::drop() }
                { Fr::drop() }

                // Both results should be true
                OP_FROMALTSTACK
                OP_FROMALTSTACK
                OP_BOOLAND
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul_by_constant() {
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for i in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let a = a.rem(&m);

            let b: BigUint = prng.sample(RandomBits::new(254));
            let b = b.rem(&m);

            let mul_by_constant = Fr::mul_by_constant(&ark_bn254::Fr::from(b.clone()));

            if i == 0 {
                println!("Fr.mul_by_constant: {} bytes", mul_by_constant.len());
            }

            let c: BigUint = a.clone().mul(b.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { mul_by_constant.clone() }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_is_field() {
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        println!("Fr.is_field: {} bytes", Fr::is_field().len());

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let a = a.rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::is_field() }
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        let a: BigUint = m.clone().add(1u8);
        let script = script! {
            { Fr::push_u32_le(&a.to_u32_digits()) }
            { Fr::is_field() }
            OP_NOT
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let a: BigUint = m.sub(1u8);
        let script = script! {
            { Fr::push_u32_le(&a.to_u32_digits()) }
            OP_NEGATE
            { Fr::is_field() }
            OP_NOT
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_convert_to_be_bytes() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let convert_to_be_bytes_script = Fr::convert_to_be_bytes();
        println!(
            "Fr.convert_to_be_bytes: {} bytes",
            convert_to_be_bytes_script.len()
        );

        for _ in 0..10 {
            let fr = ark_bn254::Fr::rand(&mut prng);
            let bytes = fr.into_bigint().to_bytes_be();

            let script = script! {
                { Fr::push_u32_le(&BigUint::from(fr).to_u32_digits()) }
                { convert_to_be_bytes_script.clone() }
                for i in 0..32 {
                    { bytes[i] } OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
