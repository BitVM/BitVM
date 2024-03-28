use crate::bn254::fp::Fp;
use crate::treepp::{pushable, script, Script};

pub struct Fp2;

impl Fp2 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        script! {
            { Fp::add(a + 1, b + 1) }
            { Fp::add(a, b + 1) }
        }
    }

    pub fn sub(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        script! {
            { Fp::sub(a + 1, b + 1) }
            { Fp::sub(a, b + 1) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fp::double(a + 1) }
            { Fp::double(a + 1) }
        }
    }

    pub fn copy(a: u32) -> Script {
        script! {
            { Fp::copy(a + 1) }
            { Fp::copy(a + 1) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            { Fp::equalverify(3, 1) }
            { Fp::equalverify(1, 0) }
        }
    }

    pub fn roll(a: u32) -> Script {
        script! {
            { Fp::roll(a + 1) }
            { Fp::roll(a + 1) }
        }
    }

    pub fn mul(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        // The degree-2 extension on BN254 Fp is under the polynomial x^2 + 1
        script! {
            { Fp::copy(a + 1) }
            { Fp::copy(b + 1 + 1) }
            { Fp::mul() }
            { Fp::copy(a + 1) }
            { Fp::copy(b + 1 + 1) }
            { Fp::mul() }
            { Fp::add(a + 2, a + 3) }
            { Fp::add(b + 3, b + 4) }
            { Fp::mul() }
            { Fp::copy(2) }
            { Fp::copy(2) }
            { Fp::sub(1, 0) }
            { Fp::add(3, 2) }
            { Fp::sub(2, 0) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp2::Fp2;
    use crate::treepp::*;
    use ark_bn254::Fq2;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::Mul;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fp2_push(element: Fq2) -> Script {
        script! {
            { Fp::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
            { Fp::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
        }
    }

    #[test]
    fn test_bn254_fp2_add() {
        println!("Fp2.add: {} bytes", Fp2::add(2, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = Fq2::rand(&mut prng);
            let b = Fq2::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fp2_push(a) }
                { fp2_push(b) }
                { Fp2::add(2, 0) }
                { fp2_push(c) }
                { Fp2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { fp2_push(a) }
                { fp2_push(b) }
                { Fp2::add(0, 2) }
                { fp2_push(c) }
                { Fp2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp2_sub() {
        println!("Fp2.sub: {} bytes", Fp2::sub(2, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = Fq2::rand(&mut prng);
            let b = Fq2::rand(&mut prng);
            let c = &a - &b;

            let script = script! {
                { fp2_push(a) }
                { fp2_push(b) }
                { Fp2::sub(2, 0) }
                { fp2_push(c) }
                { Fp2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp2_double() {
        println!("Fp2.double: {} bytes", Fp2::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = Fq2::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fp2_push(a) }
                { Fp2::double(0) }
                { fp2_push(c) }
                { Fp2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp2_mul() {
        println!("Fp2.mul: {} bytes", Fp2::mul(1, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = Fq2::rand(&mut prng);
            let b = Fq2::rand(&mut prng);
            let c = a.mul(&b);

            let script = script! {
                { fp2_push(a) }
                { fp2_push(b) }
                { Fp2::mul(2, 0) }
                { fp2_push(c) }
                { Fp2::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
