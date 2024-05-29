use bitcoin::opcodes::all::{OP_EQUALVERIFY, OP_GREATERTHAN, OP_LESSTHAN, OP_TOALTSTACK};
use sha2::digest::consts::U254;

use crate::bn254::fp254impl::Fp254Impl;

pub struct Fq;

impl Fp254Impl for Fq {
    const MODULUS: &'static str =
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    const MODULUS_LIMBS: [u32; Self::N_LIMBS as usize] = [
        0x187CFD47, 0x3082305B, 0x71CA8D3, 0x205AA45A, 0x1585D97, 0x116DA06, 0x1A029B85,
        0x139CB84C,
        0x3064,
        // 0x187cfd47, 0x10460b6, 0x1c72a34f, 0x2d522d0, 0x1585d978, 0x2db40c0, 0xa6e141, 0xe5c2634, 0x30644e
    ];

    const P_PLUS_ONE_DIV2: &'static str =
        "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4";

    const TWO_P_PLUS_ONE_DIV3: &'static str =
        "2042def740cbc01bd03583cf0100e593ba56470b9af68708d2c05d6490535385";

    const P_PLUS_TWO_DIV3: &'static str =
        "10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9c3";
    type ConstantType = ark_bn254::Fq;
}

// p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
const FQ_P: [u32; 9] = [
    0x187CFD47, 0x10460B6, 0x1C72A34F, 0x2D522D0, 0x1585D978, 0x2DB40C0, 0xA6E141, 0xE5C2634,
    0x30644E,
];
// 2²⁶¹ mod p  <=>  0xdc83629563d44755301fa84819caa36fb90a6020ce148c34e8384eb157ccc21
const FQ_R: [u32; 9] = [
    0x157CCC21, 0x141C2758, 0x185230D3, 0x14C0419, 0xAA36FB9, 0x1D4240CE, 0x11D54C07, 0x52AC7A8,
    0xDC836,
];
// inv₂₆₁ p  <=>  0x100a85dd486e7773942750342fe7cc257f6121829ae1359536782df87d1b799c77
const FQ_P_INV_261: [u32; 9] = [
    0x1B799C77, 0x16FC3E8, 0xD654D9E, 0x30535C2, 0x257F612, 0x1A17F3E6, 0xE509D40, 0x90DCEEE,
    0x100A85DD,
];

use crate::bigint::add::limb_add_carry;
use crate::bigint::sub::limb_sub_borrow;
use crate::bigint::u29x9::{u29x9_mul_karazuba, u29x9_mullo_karazuba};
use crate::bigint::BigIntImpl;
use crate::treepp::*;

pub fn fq_mul_montgomery(a: u32, b: u32) -> Script {
    return script! {
        // a b
        { u29x9_mul_karazuba(a, b) }
        // hi lo
        for i in 0..9 {
            { FQ_P_INV_261[8 - i] }
        }
        // hi lo p⁻¹
        { u29x9_mullo_karazuba(1, 0) }
        // hi lo*p⁻¹
        for i in 0..9 {
            { FQ_P[8 - i] }
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

        { FQ_P[0] } OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FQ_P[1] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FQ_P[2] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FQ_P[3] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FQ_P[4] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FQ_P[5] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FQ_P[6] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FQ_P[7] } OP_ADD OP_ADD
        { 1 << 29 } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        OP_SWAP OP_TOALTSTACK

        { FQ_P[8] } OP_ADD OP_ADD
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

        { Fq::zip(1, 0) }

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
    };
}

#[cfg(test)]
mod test {
    use crate::bn254::fq::Fq;
    use crate::bn254::{fp254impl::Fp254Impl, fq::fq_mul_montgomery};
    use crate::treepp::*;
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_std::UniformRand;
    use bitcoin::opcodes::all::OP_EQUALVERIFY;
    use core::ops::{Add, Mul, Rem, Sub};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::Num;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::bn254::fq::FQ_R;

    #[test]
    fn test_fq_mul_montgomery() {
        println!("fq_mul_montgomery: {} bytes", fq_mul_montgomery(1, 0).len());
        let script = script! {
            // Mont(1) * Mont(1)
            { FQ_R[8] } { FQ_R[7] } { FQ_R[6] } { FQ_R[5] } { FQ_R[4] } { FQ_R[3] } { FQ_R[2] } { FQ_R[1] } { FQ_R[0] }
            { FQ_R[8] } { FQ_R[7] } { FQ_R[6] } { FQ_R[5] } { FQ_R[4] } { FQ_R[3] } { FQ_R[2] } { FQ_R[1] } { FQ_R[0] }
            { fq_mul_montgomery(1, 0) }
            { FQ_R[0] } OP_EQUALVERIFY
            { FQ_R[1] } OP_EQUALVERIFY
            { FQ_R[2] } OP_EQUALVERIFY
            { FQ_R[3] } OP_EQUALVERIFY
            { FQ_R[4] } OP_EQUALVERIFY
            { FQ_R[5] } OP_EQUALVERIFY
            { FQ_R[6] } OP_EQUALVERIFY
            { FQ_R[7] } OP_EQUALVERIFY
            { FQ_R[8] } OP_EQUALVERIFY
            // 1 * 1
            OP_0 OP_0 OP_0 OP_0 OP_0 OP_0 OP_0 OP_0 OP_1
            OP_0 OP_0 OP_0 OP_0 OP_0 OP_0 OP_0 OP_0 OP_1
            { fq_mul_montgomery(1, 0) }
            { 0x584ee8b } OP_EQUALVERIFY
            { 0x1cdb2f68 } OP_EQUALVERIFY
            { 0x247987e } OP_EQUALVERIFY
            { 0x1b5610a2 } OP_EQUALVERIFY
            { 0xc602ae5 } OP_EQUALVERIFY
            { 0x1ffe0537 } OP_EQUALVERIFY
            { 0x5157382 } OP_EQUALVERIFY
            { 0xe2c8bce } OP_EQUALVERIFY
            { 0x18223d } OP_EQUALVERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        if exec_result.success == false {
            println!("ERROR: {:?} <---", exec_result.last_opcode)
        }
        assert!(exec_result.success);
    }

    #[test]
    fn test_add() {
        println!("Fq.add: {} bytes", Fq::add(0, 1).len());

        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(b.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::push_u32_le(&b.to_u32_digits()) }
                { Fq::add(1, 0) }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_sub() {
        println!("Fq.sub: {} bytes", Fq::sub(0, 1).len());

        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(&m).sub(b.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::push_u32_le(&b.to_u32_digits()) }
                { Fq::sub(1, 0) }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double() {
        println!("Fq.double: {} bytes", Fq::double(0).len());
        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        for _ in 0..100 {
            let a: BigUint = m.clone().sub(BigUint::new(vec![1]));

            let a = a.rem(&m);
            let c: BigUint = a.clone().add(a.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::double(0) }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul() {
        println!("Fq.mul: {} bytes", Fq::mul().len());
        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().mul(b.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::push_u32_le(&b.to_u32_digits()) }
                { Fq::mul() }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_square() {
        println!("Fq.square: {} bytes", Fq::square().len());
        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let c: BigUint = a.clone().mul(a.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::square() }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_neg() {
        println!("Fq.neg: {} bytes", Fq::neg(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::copy(0) }
                { Fq::neg(0) }
                { Fq::add(0, 1) }
                { Fq::push_zero() }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_inv() {
        println!("Fq.inv: {} bytes", Fq::inv().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let c = a.inverse().unwrap();

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fq::inv() }
                { Fq::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_div2() {
        println!("Fq.div2: {} bytes", Fq::div2().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fq::div2() }
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_div3() {
        println!("Fq.div3: {} bytes", Fq::div3().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let b = a.clone().double();
            let c = a.clone().add(b);

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fq::div3() }
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_is_zero() {
        println!(
            "Fq.is_zero_keep_element: {} bytes",
            Fq::is_zero_keep_element(0).len()
        );
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fq::rand(&mut prng);

            let script = script! {
                // Push three Fq elements
                { Fq::push_zero() }
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }

                // The first element should not be zero
                { Fq::is_zero_keep_element(0) }
                OP_NOT
                OP_TOALTSTACK

                // The third element should be zero
                { Fq::is_zero_keep_element(2) }
                OP_TOALTSTACK

                // Drop all three elements
                { Fq::drop() }
                { Fq::drop() }
                { Fq::drop() }

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
        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for i in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let a = a.rem(&m);

            let b: BigUint = prng.sample(RandomBits::new(254));
            let b = b.rem(&m);

            let mul_by_constant = Fq::mul_by_constant(&ark_bn254::Fq::from(b.clone()));

            if i == 0 {
                println!("Fq.mul_by_constant: {} bytes", mul_by_constant.len());
            }

            let c: BigUint = a.clone().mul(b.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { mul_by_constant.clone() }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_is_field() {
        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        println!("Fq.is_field: {} bytes", Fq::is_field().len());

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let a = a.rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::is_field() }
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        let a: BigUint = m.clone().add(1u8);
        let script = script! {
            { Fq::push_u32_le(&a.to_u32_digits()) }
            { Fq::is_field() }
            OP_NOT
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let a: BigUint = m.sub(1u8);
        let script = script! {
            { Fq::push_u32_le(&a.to_u32_digits()) }
            OP_NEGATE
            { Fq::is_field() }
            OP_NOT
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_convert_to_be_bytes() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let convert_to_be_bytes_script = Fq::convert_to_be_bytes();
        println!(
            "Fq.convert_to_be_bytes: {} bytes",
            convert_to_be_bytes_script.len()
        );

        for _ in 0..10 {
            let fq = ark_bn254::Fq::rand(&mut prng);
            let bytes = fq.into_bigint().to_bytes_be();

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(fq).to_u32_digits()) }
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
