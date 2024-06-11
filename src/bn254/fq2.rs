use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::treepp::{pushable, script, Script};
use ark_ff::Fp2Config;
use std::ops::Add;

pub struct Fq2;

impl Fq2 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        script! {
            { Fq::add(a + 1, b + 1) }
            { Fq::add(a, b + 1) }
        }
    }

    pub fn sub(a: u32, b: u32) -> Script {
        if a > b {
            script! {
                { Fq::sub(a + 1, b + 1) }
                { Fq::sub(a, b + 1) }
            }
        } else {
            script! {
                { Fq::sub(a + 1, b + 1) }
                { Fq::sub(a + 1, b) }
            }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fq::double(a + 1) }
            { Fq::double(a + 1) }
        }
    }

    /// Square the top Fq2 element
    ///
    /// Optimized by: @Hakkush-07
    pub fn square() -> Script {
        script! {
            { Fq::copy(1) }
            { Fq::copy(1) }
            { Fq::copy(1) }
            { Fq::copy(1) }
            { Fq::mul() }
            { Fq::double(0) }
            { Fq::sub(2, 1) }
            { Fq::add(3, 2) }
            { Fq::mul() }
            { Fq::roll(1) }
        }
    }

    pub fn copy(a: u32) -> Script {
        script! {
            { Fq::copy(a + 1) }
            { Fq::copy(a + 1) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            { Fq::equalverify(3, 1) }
            { Fq::equalverify(1, 0) }
        }
    }

    pub fn roll(a: u32) -> Script {
        script! {
            { Fq::roll(a + 1) }
            { Fq::roll(a + 1) }
        }
    }

    pub fn mul(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        // The degree-2 extension on BN254 Fq is under the polynomial x^2 + 1
        script! {
            { Fq::copy(a + 1) }
            { Fq::copy(b + 1 + 1) }
            { Fq::mul() }
            { Fq::copy(a + 1) }
            { Fq::copy(b + 1 + 1) }
            { Fq::mul() }
            { Fq::add(a + 2, a + 3) }
            { Fq::add(b + 3, b + 4) }
            { Fq::mul() }
            { Fq::copy(2) }
            { Fq::copy(2) }
            { Fq::sub(1, 0) }
            { Fq::add(3, 2) }
            { Fq::sub(2, 0) }
        }
    }

    pub fn mul_by_fq(mut a: u32, b: u32) -> Script {
        if a < b {
            a += 1;
        }

        script! {
            { Fq::copy(b) }
            { Fq::roll(a + 2) }
            
            { Fq::mul() }
            { Fq::roll(b + 1) }
            { Fq::roll(a + 1) }

            { Fq::mul() }
        }
    }

    pub fn push_one() -> Script {
        script! {
            { Fq::push_one() }
            { Fq::push_zero() }
        }
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq::push_zero() }
            { Fq::push_zero() }
        }
    }

    pub fn neg(a: u32) -> Script {
        script! {
            { Fq::neg(a + 1) }
            { Fq::neg(a + 1) }
        }
    }

    pub fn inv() -> Script {
        script! {
            // copy c1
            { Fq::copy(0) }

            // compute v1 = c1^2
            { Fq::square() }

            // copy c0
            { Fq::copy(2) }

            // compute v0 = c0^2 + v1
            { Fq::square() }
            { Fq::add(1, 0) }

            // compute inv v0
            { Fq::inv() }

            // dup inv v0
            { Fq::copy(0) }

            // compute c0
            { Fq::roll(3) }
            { Fq::mul() }

            // compute c1
            { Fq::roll(2) }
            { Fq::roll(2) }
            { Fq::mul() }
            { Fq::neg(0) }
        }
    }

    pub fn div2() -> Script {
        script! {
            { Fq::roll(1) }
            { Fq::div2() }
            { Fq::roll(1) }
            { Fq::div2() }
        }
    }

    pub fn div3() -> Script {
        script! {
            { Fq::roll(1) }
            { Fq::div3() }
            { Fq::roll(1) }
            { Fq::div3() }
        }
    }

    pub fn triple(a: u32) -> Script {
        script! {
            { Fq2::copy(a) }
            { Fq2::double(a + 2) }
            { Fq2::add(2, 0) }
        }
    }

    pub fn frobenius_map(i: usize) -> Script {
        script! {
            { Fq::mul_by_constant(&ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1[i % ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1.len()]) }
        }
    }

    pub fn mul_by_constant(constant: &ark_bn254::Fq2) -> Script {
        script! {
            { Fq::copy(1) }
            { Fq::mul_by_constant(&constant.c0) }
            { Fq::copy(1) }
            { Fq::mul_by_constant(&constant.c1) }
            { Fq::add(3, 2) }
            { Fq::mul_by_constant(&constant.c0.add(constant.c1)) }
            { Fq::copy(2) }
            { Fq::copy(2) }
            { Fq::add(1, 0) }
            { Fq::sub(1, 0) }
            { Fq::sub(2, 1) }
            { Fq::roll(1) }
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            { Fq::toaltstack() }
            { Fq::toaltstack() }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            { Fq::fromaltstack() }
            { Fq::fromaltstack() }
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fq::drop() }
            { Fq::drop() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    use crate::treepp::*;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::{Add, Mul};
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fq2_push(element: ark_bn254::Fq2) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
        }
    }

    fn fq2_push_montgomery(element: ark_bn254::Fq2) -> Script {
        script! {
            { Fq::push_fq_montgomery(&BigUint::from(element.c0).to_u32_digits()) }
            { Fq::push_fq_montgomery(&BigUint::from(element.c1).to_u32_digits()) }
        }
    }

    #[test]
    fn test_bn254_fq2_add() {
        println!("Fq2.add: {} bytes", Fq2::add(2, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fq2_push(a) }
                { fq2_push(b) }
                { Fq2::add(2, 0) }
                { fq2_push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { fq2_push(a) }
                { fq2_push(b) }
                { Fq2::add(0, 2) }
                { fq2_push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_sub() {
        println!("Fq2.sub: {} bytes", Fq2::sub(2, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = &a - &b;

            let script = script! {
                { fq2_push(a) }
                { fq2_push(b) }
                { Fq2::sub(2, 0) }
                { fq2_push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { fq2_push(b) }
                { fq2_push(a) }
                { Fq2::sub(0, 2) }
                { fq2_push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_double() {
        println!("Fq2.double: {} bytes", Fq2::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fq2_push_montgomery(a) }
                { Fq2::double(0) }
                { fq2_push_montgomery(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_mul() {
        println!("Fq2.mul: {} bytes", Fq2::mul(1, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = a.mul(&b);

            let script = script! {
                { fq2_push_montgomery(a) }
                { fq2_push_montgomery(b) }
                { Fq2::mul(2, 0) }
                { fq2_push_montgomery(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_mul_by_fq() {
        println!("Fq2.mul_by_fq: {} bytes", Fq2::mul_by_fq(1, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for i in 0..10 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq::rand(&mut prng);
            let mut c = a;
            c.mul_assign_by_fp(&b);

            let script = script! {
                { fq2_push_montgomery(a) }
                { Fq::push_fq_montgomery(&BigUint::from(b).to_u32_digits()) }
                { Fq2::mul_by_fq(1, 0) }
                { fq2_push_montgomery(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_inv() {
        println!("Fq2.inv: {} bytes", Fq2::inv().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.inverse().unwrap();

            let script = script! {
                { fq2_push_montgomery(a) }
                { Fq2::inv() }
                { fq2_push_montgomery(b) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_square() {
        println!("Fq2.square: {} bytes", Fq2::square().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.square();

            let script = script! {
                { fq2_push_montgomery(a) }
                { Fq2::square() }
                { fq2_push_montgomery(b) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_div2() {
        println!("Fq2.div2: {} bytes", Fq2::div2().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.double();

            let script = script! {
                { fq2_push(b) }
                { Fq2::div2() }
                { fq2_push(a) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_div3() {
        println!("Fq2.div3: {} bytes", Fq2::div3().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.double();
            let c = a.add(b);

            let script = script! {
                { fq2_push(c) }
                { Fq2::div3() }
                { fq2_push(a) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_triple() {
        println!("Fq2.triple: {} bytes", Fq2::triple(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.double();
            let c = a.add(b);

            let script = script! {
                { fq2_push(a) }
                { Fq2::triple(0) }
                { fq2_push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq2_frobenius_map() {
        println!(
            "Fq2.frobenius_map(0): {} bytes",
            Fq2::frobenius_map(0).len()
        );
        println!(
            "Fq2.frobenius_map(1): {} bytes",
            Fq2::frobenius_map(1).len()
        );

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.frobenius_map(0);

            let script = script! {
                { fq2_push(a) }
                { Fq2::frobenius_map(0) }
                { fq2_push(b) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let b = a.frobenius_map(1);

            let script = script! {
                { fq2_push(a) }
                { Fq2::frobenius_map(1) }
                { fq2_push(b) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
