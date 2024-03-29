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

    pub fn square() -> Script {
        // https://eprint.iacr.org/2009/565.pdf
        // based on the implementation in arkworks-rs, fp12_2over3over2.rs

        let sqr = || {
            script! {
                // compute tmp = ra * rb
                { Fp2::copy(2) }
                { Fp2::copy(2) }
                { Fp2::mul(2, 0) }

                // compute ra + rb
                { Fp2::copy(4) }
                { Fp2::copy(4) }
                { Fp2::add(2, 0) }

                // compute ra + beta * rb
                { Fp2::roll(4) }
                { Fp6::mul_fp2_by_nonresidue() }
                { Fp2::roll(6) }
                { Fp2::add(2, 0) }

                // compute (ra + rb) * (ra + beta * rb) - tmp - tmp * beta
                { Fp2::mul(2, 0) }
                { Fp2::copy(2) }
                { Fp6::mul_fp2_by_nonresidue() }
                { Fp2::copy(4) }
                { Fp2::add(2, 0) }
                { Fp2::sub(2, 0) }
                { Fp2::double(2) }
            }
        };

        script! {
            // copy r0 = c0.c0 and r1 = c1.c1
            { Fp2::copy(10) }
            { Fp2::copy(4) }

            // compute t0 = r0^2 + r1^2 * beta, t1 = 2r0r1
            { sqr() }

            // copy r2 = c1.c0 and r3 = c0.c2
            { Fp2::copy(8) }
            { Fp2::copy(12) }

            // compute t2 = r2^2 + r3^2 * beta, t3 = 2r2r3
            { sqr() }

            // copy r4 = c0.c1 and r5 = c1.c2
            { Fp2::copy(16) }
            { Fp2::copy(10) }

            // compute t4 = r4^2 + r5^2 * beta, t5 = 242r5
            { sqr() }

            // z0 = 2 * (t0 - r0) + t0
            { Fp2::copy(10) }
            { Fp2::roll(24) }
            { Fp2::sub(2, 0) }
            { Fp2::double(0) }
            { Fp2::roll(12) }
            { Fp2::add(2, 0) }

            // z4 = 2 * (t2 - r4) + t2
            { Fp2::copy(8) }
            { Fp2::roll(22) }
            { Fp2::sub(2, 0) }
            { Fp2::double(0) }
            { Fp2::roll(10) }
            { Fp2::add(2, 0) }

            // z3 = 2 * (t4 - r3) + t4
            { Fp2::copy(6) }
            { Fp2::roll(20) }
            { Fp2::sub(2, 0) }
            { Fp2::double(0) }
            { Fp2::roll(8) }
            { Fp2::add(2, 0) }

            // z2 = 2 * (beta * t5 + r2) + (beta * t5)
            { Fp2::roll(6) }
            { Fp6::mul_fp2_by_nonresidue() }
            { Fp2::copy(0) }
            { Fp2::roll(18) }
            { Fp2::add(2, 0) }
            { Fp2::double(0) }
            { Fp2::add(2, 0) }

            // z1 = 2 * (t1 + r1) + t1
            { Fp2::copy(10) }
            { Fp2::roll(16) }
            { Fp2::add(2, 0) }
            { Fp2::double(0) }
            { Fp2::roll(12) }
            { Fp2::add(2, 0) }

            // z5 = 2 * (t3 + r5) + t5
            { Fp2::copy(10) }
            { Fp2::roll(14) }
            { Fp2::add(2, 0) }
            { Fp2::double(0) }
            { Fp2::roll(12) }
            { Fp2::add(2, 0) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp12::Fp12;
    use crate::treepp::*;
    use ark_bn254::Fq12;
    use ark_ff::{CyclotomicMultSubgroup, Field};
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

    #[test]
    fn test_bn254_fp12_square() {
        println!("Fp12.sqr: {} bytes", Fp12::square().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = Fq12::rand(&mut prng);
            let c = a.cyclotomic_square();

            let script = script! {
                { fp12_push(a) }
                { Fp12::square() }
                { fp12_push(c) }
                { Fp12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
