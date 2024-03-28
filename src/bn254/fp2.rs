use crate::bn254::fp::Fp;
use crate::treepp::{pushable, script, Script};

pub struct Fp2;

impl Fp2 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        script! {
            { Fp::add_mod(a + 1, b + 1) }
            { Fp::add_mod(a, b + 1) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fp::double_mod(a + 1) }
            { Fp::double_mod(a + 1) }
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
            { Fp::mul_mod() }
            { Fp::copy(a + 1) }
            { Fp::copy(b + 1 + 1) }
            { Fp::mul_mod() }
            { Fp::add_mod(a + 2, a + 3) }
            { Fp::add_mod(b + 3, b + 4) }
            { Fp::mul_mod() }
            { Fp::copy(2) }
            { Fp::copy(2) }
            { Fp::sub_mod(1, 0) }
            { Fp::add_mod(3, 2) }
            { Fp::sub_mod(2, 0) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp2::Fp2;
    use crate::execute_script;
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
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { fp2_push(a) }
                { fp2_push(b) }
                { Fp2::add(0, 2) }
                { fp2_push(c) }
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
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
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
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
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
