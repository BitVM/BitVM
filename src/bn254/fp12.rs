use crate::bn254::fp::Fp;
use crate::bn254::fp2::Fp2;
use crate::bn254::fp6::Fp6;
use crate::treepp::{pushable, script, Script};

pub struct Fp12;

impl Fp12 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fp6::add(a + 6, b + 6) }
            { Fp6::add(a, b + 6) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fp6::double(a + 6) }
            { Fp6::double(a + 6) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..12 {
                { Fp::equalverify(23 - i * 2, 11 - i) }
            }
        }
    }

    pub fn mul_fp6_by_nonresidue() -> Script {
        script! {
            { Fp6::mul_fp2_by_nonresidue() }
            { Fp2::roll(4) }
            { Fp2::roll(4) }
        }
    }

    pub fn mul(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        // The degree-12 extension on BN254 Fp6 is under the polynomial z^2 - y

        script! {
            { Fp6::copy(a + 6) }
            { Fp6::copy(b + 12) }
            { Fp6::mul(6, 0) }
            { Fp6::copy(a + 6) }
            { Fp6::copy(b + 12) }
            { Fp6::mul(6, 0) }
            { Fp6::add(a + 12, a + 18) }
            { Fp6::add(b + 18, b + 24) }
            { Fp6::mul(6, 0) }
            { Fp6::copy(12) }
            { Fp6::copy(12) }
            { Fp12::mul_fp6_by_nonresidue() }
            { Fp6::add(6, 0) }
            { Fp6::add(18, 12)}
            { Fp6::sub(12, 0) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp12::Fp12;
    use crate::treepp::*;
    use ark_bn254::Fq12;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::Mul;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fp12_push(element: Fq12) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fp::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_bn254_fp12_add() {
        println!("Fp12.add: {} bytes", Fp12::add(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fp12_push(a) }
                { fp12_push(b) }
                { Fp12::add(12, 0) }
                { fp12_push(c) }
                { Fp12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp12_double() {
        println!("Fp12.double: {} bytes", Fp12::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fp12_push(a) }
                { Fp12::double(0) }
                { fp12_push(c) }
                { Fp12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp12_mul() {
        println!("Fp12.mul: {} bytes", Fp12::mul(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = Fq12::rand(&mut prng);
            let b = Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let script = script! {
                { fp12_push(a) }
                { fp12_push(b) }
                { Fp12::mul(12, 0) }
                { fp12_push(c) }
                { Fp12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
