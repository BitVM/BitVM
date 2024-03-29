use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::treepp::{pushable, script, Script};

pub struct Fq6;

impl Fq6 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fq2::add(a + 4, b + 4) }
            { Fq2::add(a + 2, b + 4) }
            { Fq2::add(a, b + 4) }
        }
    }

    pub fn sub(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fq2::sub(a + 4, b + 4) }
            { Fq2::sub(a + 2, b + 4) }
            { Fq2::sub(a, b + 4) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fq2::double(a + 4) }
            { Fq2::double(a + 4) }
            { Fq2::double(a + 4) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..6 {
                { Fq::equalverify(11 - i * 2, 5 - i) }
            }
        }
    }

    pub fn mul_fq2_by_nonresidue() -> Script {
        script! {
            { Fq2::copy(0) }
            { Fq2::double(0) }
            { Fq2::double(0) }
            { Fq2::double(0) }
            { Fq::copy(3) }
            { Fq::add(2, 0) }
            { Fq::copy(2) }
            { Fq::sub(1, 0) }
            { Fq::add(2, 1) }
            { Fq::add(2, 0) }
        }
    }

    pub fn mul(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        // The degree-6 extension on BN254 Fq2 is under the polynomial y^3 - x - 9
        // Follow https://eprint.iacr.org/2006/471.pdf, Section 4, Karatsuba

        script! {
            // compute ad
            { Fq2::copy(b + 4) }
            { Fq2::copy(a + 6) }
            { Fq2::mul(2, 0) }

            // compute be
            { Fq2::copy(b + 4) }
            { Fq2::copy(a + 6) }
            { Fq2::mul(2, 0) }

            // compute cf
            { Fq2::copy(b + 4) }
            { Fq2::copy(a + 6) }
            { Fq2::mul(2, 0) }

            // compute e + f
            { Fq2::copy(b + 8) }
            { Fq2::copy(b + 8) }
            { Fq2::add(2, 0) }

            // compute b + c
            { Fq2::copy(a + 10) }
            { Fq2::copy(a + 10) }
            { Fq2::add(2, 0) }

            // compute (e + f) * (b + c)
            { Fq2::mul(2, 0) }

            // compute x = (e + f) * (b + c) - be - cf
            { Fq2::copy(4) }
            { Fq2::copy(4) }
            { Fq2::add(2, 0) }
            { Fq2::sub(2, 0) }

            // compute d + e
            { Fq2::copy(b + 12) }
            { Fq2::roll(b + 12) }
            { Fq2::add(2, 0) }

            // compute a + b
            { Fq2::copy(a + 12) }
            { Fq2::roll(a + 12) }
            { Fq2::add(2, 0) }

            // compute (d + e) * (a + b)
            { Fq2::mul(2, 0) }

            // compute y = (d + e) * (a + b) - ad - be
            { Fq2::copy(8) }
            { Fq2::copy(8) }
            { Fq2::add(2, 0) }
            { Fq2::sub(2, 0) }

            // compute d + f
            { Fq2::roll(b + 12) }
            { Fq2::roll(b + 12) }
            { Fq2::add(2, 0) }

            // compute a + c
            { Fq2::roll(a + 8) }
            { Fq2::roll(a + 8) }
            { Fq2::add(2, 0) }

            // compute (d + f) * (a + c)
            { Fq2::mul(2, 0) }

            // compute z = (d + f) * (a + c) + be - ad - cf
            { Fq2::copy(6) }
            { Fq2::copy(12) }
            { Fq2::add(2, 0) }
            { Fq2::sub(10, 0) }
            { Fq2::add(2, 0) }

            // compute the new c0
            { Fq2::roll(4) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::add(8, 0) }

            // compute the new c1
            { Fq2::roll(6) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::add(6, 0) }

            // compute the new c2
            { Fq2::roll(4) }
        }
    }

    pub fn copy(a: u32) -> Script {
        script! {
            { Fq2::copy(a + 4) }
            { Fq2::copy(a + 4) }
            { Fq2::copy(a + 4) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq::Fq;
    use crate::bn254::fq6::Fq6;
    use crate::treepp::*;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::Mul;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fq6_push(element: ark_bn254::Fq6) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_bn254_fq6_add() {
        println!("Fq6.add: {} bytes", Fq6::add(6, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq6::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fq6_push(a) }
                { fq6_push(b) }
                { Fq6::add(6, 0) }
                { fq6_push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq6_double() {
        println!("Fq6.double: {} bytes", Fq6::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fq6_push(a) }
                { Fq6::double(0) }
                { fq6_push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq6_mul() {
        println!("Fq6.mul: {} bytes", Fq6::mul(6, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq6::rand(&mut prng);
            let c = a.mul(&b);

            let script = script! {
                { fq6_push(a) }
                { fq6_push(b) }
                { Fq6::mul(6, 0) }
                { fq6_push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
