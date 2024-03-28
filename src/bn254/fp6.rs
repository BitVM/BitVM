use crate::bn254::fp::Fp;
use crate::bn254::fp2::Fp2;
use crate::treepp::{pushable, script, Script};

pub struct Fp6;

impl Fp6 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fp2::add(a + 4, b + 4) }
            { Fp2::add(a + 2, b + 4) }
            { Fp2::add(a, b + 4) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fp2::double(a + 4) }
            { Fp2::double(a + 4) }
            { Fp2::double(a + 4) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..6 {
                { Fp::equalverify(11 - i * 2, 5 - i) }
            }
        }
    }

    pub fn mul_fp2_by_nonresidue() -> Script {
        script! {
            { Fp2::copy(0) }
            { Fp2::double(0) }
            { Fp2::double(0) }
            { Fp2::double(0) }
            { Fp::copy(3) }
            { Fp::add(2, 0) }
            { Fp::copy(2) }
            { Fp::sub(1, 0) }
            { Fp::add(2, 1) }
            { Fp::add(2, 0) }
        }
    }

    pub fn mul(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        // The degree-6 extension on BN254 Fp2 is under the polynomial y^3 - x - 9
        // Follow https://eprint.iacr.org/2006/471.pdf, Section 4, Karatsuba

        script! {
            // compute ad
            { Fp2::copy(b + 4) }
            { Fp2::copy(a + 6) }
            { Fp2::mul(2, 0) }

            // compute be
            { Fp2::copy(b + 4) }
            { Fp2::copy(a + 6) }
            { Fp2::mul(2, 0) }

            // compute cf
            { Fp2::copy(b + 4) }
            { Fp2::copy(a + 6) }
            { Fp2::mul(2, 0) }

            // compute e + f
            { Fp2::copy(b + 8) }
            { Fp2::copy(b + 8) }
            { Fp2::add(2, 0) }

            // compute b + c
            { Fp2::copy(a + 10) }
            { Fp2::copy(a + 10) }
            { Fp2::add(2, 0) }

            // compute (e + f) * (b + c)
            { Fp2::mul(2, 0) }

            // compute x = (e + f) * (b + c) - be - cf
            { Fp2::copy(4) }
            { Fp2::copy(4) }
            { Fp2::add(2, 0) }
            { Fp2::sub(2, 0) }

            // compute d + e
            { Fp2::copy(b + 12) }
            { Fp2::roll(b + 12) }
            { Fp2::add(2, 0) }

            // compute a + b
            { Fp2::copy(a + 12) }
            { Fp2::roll(a + 12) }
            { Fp2::add(2, 0) }

            // compute (d + e) * (a + b)
            { Fp2::mul(2, 0) }

            // compute y = (d + e) * (a + b) - ad - be
            { Fp2::copy(8) }
            { Fp2::copy(8) }
            { Fp2::add(2, 0) }
            { Fp2::sub(2, 0) }

            // compute d + f
            { Fp2::roll(b + 12) }
            { Fp2::roll(b + 12) }
            { Fp2::add(2, 0) }

            // compute a + c
            { Fp2::roll(a + 8) }
            { Fp2::roll(a + 8) }
            { Fp2::add(2, 0) }

            // compute (d + f) * (a + c)
            { Fp2::mul(2, 0) }

            // compute z = (d + f) * (a + c) + be - ad - cf
            { Fp2::copy(6) }
            { Fp2::copy(12) }
            { Fp2::add(2, 0) }
            { Fp2::sub(10, 0) }
            { Fp2::add(2, 0) }

            // compute the new c0
            { Fp2::roll(4) }
            { Fp6::mul_fp2_by_nonresidue() }
            { Fp2::add(8, 0) }

            // compute the new c1
            { Fp2::roll(6) }
            { Fp6::mul_fp2_by_nonresidue() }
            { Fp2::add(6, 0) }

            // compute the new c2
            { Fp2::roll(4) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp6::Fp6;
    use crate::treepp::*;
    use ark_bn254::Fq6;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::Mul;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fp6_push(element: Fq6) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fp::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_bn254_fp6_add() {
        println!("Fp6.add: {} bytes", Fp6::add(6, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = Fq6::rand(&mut prng);
            let b = Fq6::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fp6_push(a) }
                { fp6_push(b) }
                { Fp6::add(6, 0) }
                { fp6_push(c) }
                { Fp6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp6_double() {
        println!("Fp6.double: {} bytes", Fp6::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = Fq6::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fp6_push(a) }
                { Fp6::double(0) }
                { fp6_push(c) }
                { Fp6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp6_mul() {
        println!("Fp6.mul: {} bytes", Fp6::mul(6, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = Fq6::rand(&mut prng);
            let b = Fq6::rand(&mut prng);
            let c = a.mul(&b);

            let script = script! {
                { fp6_push(a) }
                { fp6_push(b) }
                { Fp6::mul(6, 0) }
                { fp6_push(c) }
                { Fp6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(
                exec_result.success,
                "{:?} {:?}",
                exec_result.error, exec_result.final_stack
            );
        }
    }
}
