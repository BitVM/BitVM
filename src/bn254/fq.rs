
use crate::bn254::fp254impl::Fp254Impl;


pub struct Fq;

impl Fp254Impl for Fq {
    const MODULUS: &'static str =
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    // 2²⁶¹ mod p  <=>  0xdc83629563d44755301fa84819caa36fb90a6020ce148c34e8384eb157ccc21
    const MONTGOMERY_ONE: &'static str =
        "dc83629563d44755301fa84819caa36fb90a6020ce148c34e8384eb157ccc21";

    // p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
    const MODULUS_LIMBS: [u32; Self::N_LIMBS as usize] = [
        0x187cfd47, 0x10460b6, 0x1c72a34f, 0x2d522d0, 0x1585d978, 0x2db40c0, 0xa6e141, 0xe5c2634, 0x30644e
    ];

    // inv₂₆₁ p  <=>  0x100a85dd486e7773942750342fe7cc257f6121829ae1359536782df87d1b799c77
    const MODULUS_INV_261: [u32; Self::N_LIMBS as usize] = [
        0x1B799C77, 0x16FC3E8, 0xD654D9E, 0x30535C2, 0x257F612, 0x1A17F3E6, 0xE509D40, 0x90DCEEE, 0x100A85DD
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
    use crate::bn254::fq::Fq;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bigint::U254;
    use crate::treepp::*;
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_std::UniformRand;

    use core::ops::{Add, Mul, Rem, Sub};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::Num;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use ark_ff::AdditiveGroup;

    #[test]
    fn test_decode_montgomery() {
        println!("Fq.decode_montgomery: {} bytes", Fq::decode_montgomery().len());
        let script = script! {
            { Fq::push_one() }
            { Fq::push_u32_le(&BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap().to_u32_digits()) }
            { Fq::decode_montgomery() }
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
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
        let script = script! {
            // Mont(1) * Mont(1)
            { Fq::push_one() }
            { Fq::push_one() }
            { Fq::mul() }
            { 0x157CCC21 } OP_EQUALVERIFY
            { 0x141C2758 } OP_EQUALVERIFY
            { 0x185230D3 } OP_EQUALVERIFY
            { 0x14C0419 } OP_EQUALVERIFY
            { 0xAA36FB9 } OP_EQUALVERIFY
            { 0x1D4240CE } OP_EQUALVERIFY
            { 0x11D54C07 } OP_EQUALVERIFY
            { 0x52AC7A8 } OP_EQUALVERIFY
            { 0xDC836 } OP_EQUALVERIFY
            // 1 * 1
            { U254::push_one() }
            { U254::push_one() }
            { Fq::mul() }
            { 0x584ee8b } OP_EQUALVERIFY
            { 0x1cdb2f68 } OP_EQUALVERIFY
            { 0x247987e } OP_EQUALVERIFY
            { 0x1b5610a2 } OP_EQUALVERIFY
            { 0xc602ae5 } OP_EQUALVERIFY
            { 0x1ffe0537 } OP_EQUALVERIFY
            { 0x5157382 } OP_EQUALVERIFY
            { 0xe2c8bce } OP_EQUALVERIFY
            { 0x18223d } OP_EQUALVERIFY

            // NOTE: Debugging Fq2::mul_by_fq

            { Fq::push_hex("1eaea6410b7b58843c06c0d8fca3dc0a7d82b11dfd91b7cb0c0ad3ba0ff345d8") } // a.c0
            { Fq::push_hex("2adca7063c3e4dd8c35651e75e9feb1d044425f7b9bea3692eb980797d8988a4") } // b
            { Fq::mul() }
            { Fq::push_hex("300d597ee82eaa630fdd084fd83805977b383d68c9bcc1363aa85368abf77bc9") } // c.c0
            { Fq::equalverify(1, 0) }

            { Fq::push_hex("116ec221126bf493b71e1e746a3abed3b8006c4af6720dd9272fa65e3d6ee095") } // a.c1
            { Fq::push_hex("2adca7063c3e4dd8c35651e75e9feb1d044425f7b9bea3692eb980797d8988a4") } // b
            { Fq::mul() }
            { Fq::push_hex("155d7d7c80e274580d99b001eb02c88b736321f9fdbd02c88dee511f74f45447") } // c.c1
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_square() {
        println!("Fq.square: {} bytes", Fq::square().len());
        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..10 {
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

        for _ in 0..10 {
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

        for _ in 0..10 {
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
            let c = a.add(b);

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

        for i in 0..10 {
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

        let script = script! {
            { Fq::push_modulus() } OP_1 OP_ADD
            { Fq::is_field() }
            OP_NOT
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let script = script! {
            { Fq::push_modulus() } OP_1 OP_SUB
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
