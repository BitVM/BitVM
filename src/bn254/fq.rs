use crate::bn254::fp254impl::Fp254Impl;

pub struct Fq;

impl Fp254Impl for Fq {
    const MODULUS: &'static str =
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    const MODULUS_LIMBS: [u32; Self::N_LIMBS as usize] = [
        0x187CFD47, 0x3082305B, 0x71CA8D3, 0x205AA45A, 0x1585D97, 0x116DA06, 0x1A029B85,
        0x139CB84C, 0x3064,
    ];

    const P_PLUS_ONE_DIV2: &'static str =
        "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4";

    const TWO_P_PLUS_ONE_DIV3: &'static str =
        "2042def740cbc01bd03583cf0100e593ba56470b9af68708d2c05d6490535385";

    const P_PLUS_TWO_DIV3: &'static str =
        "10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9c3";
    type ConstantType = ark_bn254::Fq;
}

#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
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
