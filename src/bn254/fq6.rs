use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::treepp::{script, Script};
use ark_ff::Fp6Config;
use num_bigint::BigUint;

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

    pub fn sub(a: u32, b: u32) -> Script {
        if a > b {
            script! {
                { Fq2::sub(a + 4, b + 4) }
                { Fq2::sub(a + 2, b + 4) }
                { Fq2::sub(a, b + 4) }
            }
        } else {
            script! {
                { Fq2::sub(a + 4, b + 4) }
                { Fq2::sub(a + 4, b + 2) }
                { Fq2::sub(a + 4, b) }
            }
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

    // input:
    //   p  (6 elements)
    //   x  (2 elements)
    pub fn mul_by_fp2() -> Script {
        script! {
            // compute p.c0 * c0
            { Fq2::roll(6) }
            { Fq2::copy(2) }
            { Fq2::mul(2, 0) }

            // compute p.c1 * c1
            { Fq2::roll(6) }
            { Fq2::copy(4) }
            { Fq2::mul(2, 0) }

            // compute p.c2 * c2
            { Fq2::roll(6) }
            { Fq2::roll(6) }
            { Fq2::mul(2, 0) }
        }
    }

    pub fn mul_by_fp2_constant(constant: &ark_bn254::Fq2) -> Script {
        script! {
            // compute p.c0 * c0
            { Fq2::roll(4) }
            { Fq2::mul_by_constant(constant) }

            // compute p.c1 * c1
            { Fq2::roll(4) }
            { Fq2::mul_by_constant(constant) }

            // compute p.c2 * c2
            { Fq2::roll(4) }
            { Fq2::mul_by_constant(constant) }
        }
    }

    pub fn push_one() -> Script {
        script! {
            { Fq2::push_one() }
            { Fq2::push_zero() }
            { Fq2::push_zero() }
        }
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq2::push_zero() }
            { Fq2::push_zero() }
            { Fq2::push_zero() }
        }
    }

    pub fn mul(mut a: u32, mut b: u32) -> Script {
        // The degree-6 extension on BN254 Fq2 is under the polynomial y^3 - x - 9
        // Toom-Cook-3 from https://eprint.iacr.org/2006/471.pdf
        if a < b {
            (a, b) = (b, a);
        }

        script! {
            // compute ad = P(0)
            { Fq2::copy(b + 4) }
            { Fq2::copy(a + 6) }
            { Fq2::mul(2, 0) }

            // compute a+c
            { Fq2::copy(a + 6) }
            { Fq2::copy(a + 4) }
            { Fq2::add(2, 0) }

            // compute a+b+c, a-b+c
            { Fq2::copy(0) }
            { Fq2::copy(a + 8) }
            { Fq2::copy(0) }
            { Fq2::add(4, 0) }
            { Fq2::sub(4, 2) }

            // compute d+f
            { Fq2::copy(b + 10) }
            { Fq2::copy(b + 8) }
            { Fq2::add(2, 0) }

            // compute d+e+f, d-e+f
            { Fq2::copy(0) }
            { Fq2::copy(b + 12) }
            { Fq2::copy(0) }
            { Fq2::add(4, 0) }
            { Fq2::sub(4, 2) }

            // compute (a+b+c)(d+e+f) = P(1)
            { Fq2::mul(6, 2) }

            // compute (a-b+c)(d-e+f) = P(-1)
            { Fq2::mul(4, 2) }

            // compute 2b
            { Fq2::roll(a + 8) }
            { Fq2::double(0) }

            // compute 4c
            { Fq2::copy(a + 8) }
            { Fq2::double(0) }
            { Fq2::double(0) }

            // compute a+2b+4c
            { Fq2::add(2, 0) }
            { Fq2::roll(a + 10) }
            { Fq2::add(2, 0) }

            // compute 2e
            { Fq2::roll(b + 10) }
            { Fq2::double(0) }

            // compute 4f
            { Fq2::copy(b + 10) }
            { Fq2::double(0) }
            { Fq2::double(0) }

            // compute d+2e+4f
            { Fq2::add(2, 0) }
            { Fq2::roll(b + 12) }
            { Fq2::add(2, 0) }

            // compute (a+2b+4c)(d+2e+4f) = P(2)
            { Fq2::mul(2, 0) }

            // compute cf = P(inf)
            { Fq2::roll(b + 8) }
            { Fq2::roll(a + 4) }
            { Fq2::mul(2, 0) }

            // // at this point, we have v_0, v_1, v_2, v_3, v_4

            // compute 3v_0
            { Fq2::triple(8) }

            // compute 3v_1
            { Fq2::triple(8) }

            // compute 6v_4
            { Fq2::triple(4) }
            { Fq2::double(0) }

            // compute x = 3v_0 - 3v_1 - v_2 + v_3 - 12v_4
            { Fq2::copy(4) }
            { Fq2::copy(4) }
            { Fq2::sub(2, 0) }
            { Fq2::copy(10) }
            { Fq2::sub(2, 0) }
            { Fq2::copy(8) }
            { Fq2::add(2, 0) }
            { Fq2::copy(2) }
            { Fq2::double(0) }
            { Fq2::sub(2, 0) }

            // compute c_0 = 6v_0 + \beta x
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::copy(6) }
            { Fq2::double(0) }
            { Fq2::add(2, 0) }

            // compute y = -3v_0 + 6v_1 - 2v_2 - v_3 + 12v_4
            { Fq2::copy(4) }
            { Fq2::double(0) }
            { Fq2::copy(8) }
            { Fq2::sub(2, 0) }
            { Fq2::copy(12) }
            { Fq2::double(0) }
            { Fq2::sub(2, 0) }
            { Fq2::roll(10) }
            { Fq2::sub(2, 0) }
            { Fq2::copy(4) }
            { Fq2::double(0) }
            { Fq2::add(2, 0) }

            // compute c_1 = y + \beta 6v_4
            { Fq2::copy(4) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::add(2, 0) }

            // compute c_2 = 3v_1 - 6v_0 + 3v_2 - 6v_4
            { Fq2::roll(6) }
            { Fq2::roll(8) }
            { Fq2::double(0) }
            { Fq2::sub(2, 0) }
            { Fq2::roll(8) }
            { Fq2::triple(0) }
            { Fq2::add(2, 0) }
            { Fq2::sub(0, 6) }

            // divide by 6
            { Fq2::roll(4) }
            { Fq2::div2() }
            { Fq2::div3() }
            { Fq2::roll(4) }
            { Fq2::div2() }
            { Fq2::div3() }
            { Fq2::roll(4) }
            { Fq2::div2() }
            { Fq2::div3() }
        }
    }

    // input:
    //    p.c0   (2 elements)
    //    p.c1   (2 elements)
    //    p.c2   (2 elements)
    //    c0  (2 elements)
    //    c1  (2 elements)
    pub fn mul_by_01() -> Script {
        script! {
            // compute a_a = p.c0 * c0
            { Fq2::copy(8) }
            { Fq2::copy(4) }
            { Fq2::mul(2, 0) }

            // compute b_b = p.c1 * c1
            { Fq2::copy(8) }
            { Fq2::copy(4) }
            { Fq2::mul(2, 0) }

            // compute tmp = p.c1 + p.c2
            { Fq2::copy(10) }
            { Fq2::copy(10) }
            { Fq2::add(2, 0) }

            // t1 = c1 * tmp
            { Fq2::copy(6) }
            { Fq2::mul(2, 0) }

            // t1 = t1 - b_b
            { Fq2::copy(2) }
            { Fq2::sub(2, 0) }

            // t1 = t1 * nonresidue
            { Fq6::mul_fq2_by_nonresidue() }

            // t1 = t1 + a_a
            { Fq2::copy(4) }
            { Fq2::add(2, 0) }

            // compute tmp = p.c0 + p.c1
            { Fq2::copy(14) }
            { Fq2::roll(14) }
            { Fq2::add(2, 0) }

            // t2 = c0 + c1
            { Fq2::copy(10) }
            { Fq2::roll(10) }
            { Fq2::add(2, 0) }

            // t2 = t2 * tmp
            { Fq2::mul(2, 0) }

            // t2 = t2 - a_a
            { Fq2::copy(6) }
            { Fq2::sub(2, 0) }

            // t2 = t2 - b_b
            { Fq2::copy(4) }
            { Fq2::sub(2, 0) }

            // compute tmp = p.c0 + p.c2
            { Fq2::add(12, 10) }

            // t3 = c0 * tmp
            { Fq2::mul(10, 0) }

            // t3 = t3 - a_a
            { Fq2::sub(0, 8) }

            // t3 = t3 + b_b
            { Fq2::add(0, 6) }
        }
    }

    // input:
    //    p.c0   (2 elements)
    //    p.c1   (2 elements)
    //    p.c2   (2 elements)
    //    c0     (2 elements)
    pub fn mul_by_01_with_1_constant(constant: &ark_bn254::Fq2) -> Script {
        script! {
            // compute a_a = p.c0 * c0
            { Fq2::copy(6) }
            { Fq2::copy(2) }
            { Fq2::mul(2, 0) }

            // compute b_b = p.c1 * c1
            { Fq2::copy(6) }
            { Fq2::mul_by_constant(constant) }

            // compute tmp = p.c1 + p.c2
            { Fq2::copy(8) }
            { Fq2::copy(8) }
            { Fq2::add(2, 0) }

            // t1 = c1 * tmp
            { Fq2::mul_by_constant(constant) }

            // t1 = t1 - b_b
            { Fq2::copy(2) }
            { Fq2::sub(2, 0) }

            // t1 = t1 * nonresidue
            { Fq6::mul_fq2_by_nonresidue() }

            // t1 = t1 + a_a
            { Fq2::copy(4) }
            { Fq2::add(2, 0) }

            // compute tmp = p.c0 + p.c1
            { Fq2::copy(12) }
            { Fq2::roll(12) }
            { Fq2::add(2, 0) }

            // t2 = c0 + c1
            { Fq2::copy(8) }
            { Fq::push_u32_le(&BigUint::from(constant.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(constant.c1).to_u32_digits()) }
            { Fq2::add(2, 0) }

            // t2 = t2 * tmp
            { Fq2::mul(2, 0) }

            // t2 = t2 - a_a
            { Fq2::copy(6) }
            { Fq2::sub(2, 0) }

            // t2 = t2 - b_b
            { Fq2::copy(4) }
            { Fq2::sub(2, 0) }

            // compute tmp = p.c0 + p.c2
            { Fq2::add(12, 10) }

            // t3 = c0 * tmp
            { Fq2::mul(10, 0) }

            // t3 = t3 - a_a
            { Fq2::sub(0, 8) }

            // t3 = t3 + b_b
            { Fq2::add(0, 6) }
        }
    }

    /// Square the top Fq6 element
    ///
    /// Optimized by: @Hakkush-07
    pub fn square() -> Script {
        // CH-SQR3 from https://eprint.iacr.org/2006/471.pdf
        script! {
            // compute s_0 = a_0 ^ 2
            { Fq2::copy(4) }
            { Fq2::square() }

            // compute a_0 + a_2
            { Fq2::roll(6) }
            { Fq2::copy(4) }
            { Fq2::add(2, 0) }

            // compute s_1 = (a_0 + a_1 + a_2) ^ 2
            { Fq2::copy(0) }
            { Fq2::copy(8) }
            { Fq2::add(2, 0) }
            { Fq2::square() }

            // compute s_2 = (a_0 - a_1 + a_2) ^ 2
            { Fq2::copy(8) }
            { Fq2::sub(4, 0) }
            { Fq2::square() }

            // compute s_3 = 2a_1a_2
            { Fq2::roll(8) }
            { Fq2::copy(8) }
            { Fq2::mul(2, 0) }
            { Fq2::double(0) }

            // compute s_4 = a_2 ^ 2
            { Fq2::roll(8) }
            { Fq2::square() }

            // compute t_1 = (s_1 + s_2) / 2
            { Fq2::copy(6) }
            { Fq2::roll(6) }
            { Fq2::add(2, 0) }
            { Fq2::div2() }

            // at this point, we have s_0, s_1, s_3, s_4, t_1

            // compute c_0 = s_0 + \beta s_3
            { Fq2::copy(4) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::copy(10) }
            { Fq2::add(2, 0) }

            // compute c_1 = s_1 - s_3 - t_1 + \beta s_4
            { Fq2::copy(4) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::copy(4) }
            { Fq2::add(10, 0) }
            { Fq2::sub(10, 0) }
            { Fq2::add(2, 0) }

            // compute c_2 = t_1 - s_0 - s_4
            { Fq2::add(8, 6) }
            { Fq2::sub(6, 0) }
        }
    }

    pub fn copy(a: u32) -> Script {
        script! {
            { Fq2::copy(a + 4) }
            { Fq2::copy(a + 4) }
            { Fq2::copy(a + 4) }
        }
    }

    pub fn roll(a: u32) -> Script {
        script! {
            { Fq2::roll(a + 4) }
            { Fq2::roll(a + 4) }
            { Fq2::roll(a + 4) }
        }
    }

    pub fn neg(a: u32) -> Script {
        script! {
            { Fq2::neg(a + 4) }
            { Fq2::neg(a + 4) }
            { Fq2::neg(a + 4) }
        }
    }

    pub fn inv() -> Script {
        script! {
            // compute t0 = c0^2, t1 = c1^2, t2 = c2^2
            { Fq2::copy(4) }
            { Fq2::square() }
            { Fq2::copy(4) }
            { Fq2::square() }
            { Fq2::copy(4) }
            { Fq2::square() }

            // compute t3 = c0 * c1, t4 = c0 * c2, t5 = c1 * c2
            { Fq2::copy(10) }
            { Fq2::copy(10) }
            { Fq2::mul(2, 0) }
            { Fq2::copy(12) }
            { Fq2::copy(10) }
            { Fq2::mul(2, 0) }
            { Fq2::copy(12) }
            { Fq2::copy(12) }
            { Fq2::mul(2, 0) }

            // update t5 = t5 * beta
            { Fq6::mul_fq2_by_nonresidue() }

            // compute s0 = t0 - t5
            { Fq2::sub(10, 0) }

            // compute s1 = t2 * beta - t3
            { Fq2::roll(6) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::sub(0, 6) }

            // compute s2 = t1 - t4
            { Fq2::sub(6, 4) }

            // compute a1 = c2 * s1
            { Fq2::copy(2) }
            { Fq2::mul(8, 0) }

            // compute a2 = c1 * s2
            { Fq2::copy(2) }
            { Fq2::mul(10, 0) }

            // compute a3 = beta * (a1 + a2)
            { Fq2::add(2, 0) }
            { Fq6::mul_fq2_by_nonresidue() }

            // compute t6 = c0 * s0 + a3
            { Fq2::copy(6) }
            { Fq2::mul(10, 0) }
            { Fq2::add(2, 0) }

            // inverse t6
            { Fq2::inv() }

            // compute final c0 = s0 * t6
            { Fq2::copy(0) }
            { Fq2::mul(8, 0) }

            // compute final c1 = s1 * t6
            { Fq2::copy(2) }
            { Fq2::mul(8, 0) }

            // compute final c2 = s2 * t6
            { Fq2::mul(6, 4) }
        }
    }

    pub fn frobenius_map(i: usize) -> Script {
        script! {
            { Fq2::roll(4) }
            { Fq2::frobenius_map(i) }
            { Fq2::roll(4) }
            { Fq2::frobenius_map(i) }
            { Fq2::mul_by_constant(&ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1[i % ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1.len()]) }
            { Fq2::roll(4) }
            { Fq2::frobenius_map(i) }
            { Fq2::mul_by_constant(&ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2[i % ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2.len()]) }
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            { Fq2::toaltstack() }
            { Fq2::toaltstack() }
            { Fq2::toaltstack() }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            { Fq2::fromaltstack() }
            { Fq2::fromaltstack() }
            { Fq2::fromaltstack() }
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fq2::drop() }
            { Fq2::drop() }
            { Fq2::drop() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq6::Fq6;
    use crate::bn254::utils::{fq2_push, fq6_push};
    use crate::treepp::*;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::Mul;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

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
    fn test_bn254_fq6_sub() {
        println!("Fq6.sub: {} bytes", Fq6::sub(6, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq6::rand(&mut prng);
            let c = &a - &b;

            let script = script! {
                { fq6_push(a) }
                { fq6_push(b) }
                { Fq6::sub(6, 0) }
                { fq6_push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { fq6_push(b) }
                { fq6_push(a) }
                { Fq6::sub(0, 6) }
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

    #[test]
    fn test_bn254_fq6_mul_by_01() {
        println!("Fq6.mul_by_01: {} bytes", Fq6::mul_by_01().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let c0 = ark_bn254::Fq2::rand(&mut prng);
            let c1 = ark_bn254::Fq2::rand(&mut prng);
            let mut b = a;
            b.mul_by_01(&c0, &c1);

            let script = script! {
                { fq6_push(a) }
                { fq2_push(c0) }
                { fq2_push(c1) }
                { Fq6::mul_by_01() }
                { fq6_push(b) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul_by_fp2() {
        println!("Fq6.mul_by_fp2: {} bytes", Fq6::mul_by_fp2().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let mut c = a;
            c.mul_by_fp2(&b);

            let script = script! {
                { fq6_push(a) }
                { fq2_push(b) }
                { Fq6::mul_by_fp2() }
                { fq6_push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq6_inv() {
        println!("Fq6.inv: {} bytes", Fq6::inv().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = a.inverse().unwrap();

            let script = script! {
                { fq6_push(a) }
                { Fq6::inv() }
                { fq6_push(b) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq6_square() {
        println!("Fq6.square: {} bytes", Fq6::square().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = a.square();

            let script = script! {
                { fq6_push(a) }
                { Fq6::square() }
                { fq6_push(b) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq6_frobenius_map() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            for i in 0..6 {
                let a = ark_bn254::Fq6::rand(&mut prng);
                let b = a.frobenius_map(i);

                let frobenius_map = Fq6::frobenius_map(i);
                println!("Fq6.frobenius_map({}): {} bytes", i, frobenius_map.len());

                let script = script! {
                    { fq6_push(a) }
                    { frobenius_map.clone() }
                    { fq6_push(b) }
                    { Fq6::equalverify() }
                    OP_TRUE
                };
                let exec_result = execute_script(script);
                assert!(exec_result.success);
            }
        }
    }
}
