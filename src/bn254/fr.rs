use crate::bn254::fp254impl::Fp254Impl;

pub struct Fr;

impl Fp254Impl for Fr {
    const MODULUS: &'static str =
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    // 2²⁶¹ mod p  <=>  0xdc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57
    const MONTGOMERY_ONE: &'static str =
        "dc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57";

    // p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    const MODULUS_LIMBS: [u32; Self::N_LIMBS as usize] = [
        0x10000001, 0x1f0fac9f, 0xe5c2450, 0x7d090f3, 0x1585d283, 0x2db40c0, 0xa6e141, 0xe5c2634,
        0x30644e,
    ];
    // inv₂₆₁ p  <=>  0xd8c07d0e2f27cbe4d1c6567d766f9dc6e9a7979b4b396ee4c3d1e0a6c10000001
    const MODULUS_INV_261: [u32; Self::N_LIMBS as usize] = [
        0x10000001, 0x8f05360, 0x5bb930f, 0x12f36967, 0x1dc6e9a7, 0x13ebb37c, 0x19347195,
        0x1c5e4f97, 0xd8c07d0,
    ];

    const P_PLUS_ONE_DIV2: &'static str =
        "183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001";

    const TWO_P_PLUS_ONE_DIV3: &'static str =
        "2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001";

    const P_PLUS_TWO_DIV3: &'static str =
        "10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a73150000001";
    type ConstantType = ark_bn254::Fr;
}

#[cfg(test)]
mod test {
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use crate::{bn254::fp254impl::Fp254Impl, run_as_chunks};
    use ark_ff::AdditiveGroup;
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_std::UniformRand;
    use core::ops::{Add, Mul, Rem, Sub};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::Num;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_decode_montgomery() {
        println!(
            "Fr.decode_montgomery: {} bytes",
            Fr::decode_montgomery().len()
        );
        let script = script! {
            { Fr::push_one() }
            { Fr::push_u32_le(&BigUint::from_str_radix(Fr::MONTGOMERY_ONE, 16).unwrap().to_u32_digits()) }
            { Fr::decode_montgomery() }
            { Fr::equalverify(1, 0) }
            OP_TRUE
        };
        run(script);
    }

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
            run(script);
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
            run(script);
        }
    }

    #[test]
    fn test_sub_as_chunks_fr() {
        println!("Fr.sub: {} bytes", Fr::sub(0, 1).len());

        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

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
        run_as_chunks(script, 100, 19)
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
            run(script);
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
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::push_u32_le(&b.to_u32_digits()) }
                { Fr::mul() }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_square() {
        println!("Fr.square: {} bytes", Fr::square().len());
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let c: BigUint = a.clone().mul(a.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::square() }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_neg() {
        println!("Fr.neg: {} bytes", Fr::neg(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
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
            run(script);
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
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::inv() }
                { Fr::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_div2() {
        println!("Fr.div2: {} bytes", Fr::div2().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fr::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fr::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fr::div2() }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
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
            run(script);
        }
    }

    #[test]
    fn test_is_one() {
        println!("Fr.is_one: {} bytes", Fr::is_one(0).len());
        println!(
            "Fr.is_one_keep_element: {} bytes",
            Fr::is_one_keep_element(0).len()
        );
        let script = script! {
            { Fr::push_one() }
            { Fr::is_one_keep_element(0) }
            OP_TOALTSTACK
            { Fr::is_one(0) }
            OP_FROMALTSTACK
            OP_BOOLAND
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_is_zero() {
        println!("Fr.is_zero: {} bytes", Fr::is_zero(0).len());
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
                { Fr::push_zero() }
                { Fr::is_zero(0) }
                OP_BOOLAND
            };
            run(script);
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
            run(script);
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
            run(script);
        }

        let script = script! {
            { Fr::push_modulus() } OP_1 OP_ADD
            { Fr::is_field() }
            OP_NOT
        };
        run(script);

        let script = script! {
            { Fr::push_modulus() } OP_1 OP_SUB
            OP_NEGATE
            { Fr::is_field() }
            OP_NOT
        };
        run(script);
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
        run(script);
        }
    }
}
