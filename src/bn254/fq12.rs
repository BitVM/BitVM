use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::fr::Fr;
use crate::treepp::{script, Script};
use ark_ff::{Field, Fp12Config};
use num_bigint::BigUint;
use num_traits::{Num, Zero};
use std::ops::{ShrAssign, Sub};

use super::utils::Hint;

pub struct Fq12;

impl Fq12 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fq6::add(a + 6, b + 6) }
            { Fq6::add(a, b + 6) }
        }
    }

    pub fn sub(a: u32, b: u32) -> Script {
        if a > b {
            script! {
                { Fq6::sub(a + 6, b + 6) }
                { Fq6::sub(a, b + 6) }
            }
        } else {
            script! {
                { Fq6::sub(a + 6, b + 6) }
                { Fq6::sub(a + 6, b) }
            }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fq6::double(a + 6) }
            { Fq6::double(a + 6) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..12 {
                { Fq::equalverify(23 - i * 2, 11 - i) }
            }
        }
    }

    pub fn mul_fq6_by_nonresidue() -> Script {
        script! {
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::roll(4) }
            { Fq2::roll(4) }
        }
    }

    pub fn push_one() -> Script {
        script! {
            { Fq6::push_one() }
            { Fq6::push_zero() }
        }
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq6::push_zero() }
            { Fq6::push_zero() }
        }
    }

    pub fn mul(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        // The degree-12 extension on BN254 Fq6 is under the polynomial z^2 - y

        // TODO:
        //  should be possible to save the stack space by using the lower limbs to store the
        //  sum of high-low limbs after the first multiplication is done.

        script! {
            { Fq6::copy(a + 6) }
            { Fq6::copy(b + 12) }
            { Fq6::mul(6, 0) }
            { Fq6::copy(a + 6) }
            { Fq6::copy(b + 12) }
            { Fq6::mul(6, 0) }
            { Fq6::add(a + 12, a + 18) }
            { Fq6::add(b + 18, b + 24) }
            { Fq6::mul(6, 0) }
            { Fq6::copy(12) }
            { Fq6::copy(12) }
            { Fq12::mul_fq6_by_nonresidue() }
            { Fq6::add(6, 0) }
            { Fq6::add(18, 12)}
            { Fq6::sub(12, 0) }
        }
    }

    pub fn hinted_mul(mut a_depth: u32, mut a: ark_bn254::Fq12, mut b_depth: u32, mut b: ark_bn254::Fq12) -> (Script, Vec<Hint>) {
        if a_depth < b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }
        assert_ne!(a_depth, b_depth);
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_mul(6, a.c0, 0, b.c0);
        let (hinted_script2, hint2) = Fq6::hinted_mul(6, a.c1, 0, b.c1);
        let (hinted_script3, hint3) = Fq6::hinted_mul(6, a.c0+a.c1, 0, b.c0+b.c1);

        let mut script = script! {};
        let script_lines = [
            Fq6::copy(a_depth + 6),
            Fq6::copy(b_depth + 12),
            hinted_script1,
            Fq6::copy(a_depth + 6),
            Fq6::copy(b_depth + 12),
            hinted_script2,
            Fq6::add(a_depth + 12, a_depth + 18),
            Fq6::add(b_depth + 18, b_depth + 24),
            hinted_script3,
            Fq6::copy(12),
            Fq6::copy(12),
            Fq12::mul_fq6_by_nonresidue(),
            Fq6::add(6, 0),
            Fq6::add(18, 12),
            Fq6::sub(12, 0),
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);

        (script, hints)
    }

    pub fn mul_cpt(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        // a0, a1, b0, b1
        script! {
            { Fq6::copy(a + 6) }
            // a0, a1, b0, b1, a0
            { Fq6::copy(b + 12) }
            // a0, a1, b0, b1, a0, b0
            { Fq6::mul(6, 0) }
            // a0, a1, b0, b1, a0 * b0
            { Fq6::roll(a + 12) }
            // a1, b0, b1, a0 * b0, a0
            { Fq6::copy(a + 12) }
            // a1, b0, b1, a0 * b0, a0, a1
            { Fq6::add(6, 0) }
            // a1, b0, b1, a0 * b0, a0 + a1
            { Fq6::roll(b + 18) }
            // a1, b1, a0 * b0, a0 + a1, b0
            { Fq6::copy(b + 18) }
            // a1, b1, a0 * b0, a0 + a1, b0, b1
            { Fq6::add(6, 0) }
            // a1, b1, a0 * b0, a0 + a1, b0 + b1
            { Fq6::mul(6, 0) }
            // a1, b1, a0 * b0, (a0 + a1) * (b0 + b1)
            { Fq6::mul(a + 6, b + 12) }
            // a0 * b0, (a0 + a1) * (b0 + b1), a1 * b1
            { Fq6::copy(0) }
            // a0 * b0, (a0 + a1) * (b0 + b1), a1 * b1, a1 * b1
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::roll(4) }
            { Fq2::roll(4) }
            // a0 * b0, (a0 + a1) * (b0 + b1), a1 * b1, a1 * b1 * beta
            { Fq6::copy(18) }
            // a0 * b0, (a0 + a1) * (b0 + b1), a1 * b1, a1 * b1 * beta, a0 * b0
            { Fq6::add(6, 0) }
            // a0 * b0, (a0 + a1) * (b0 + b1), a1 * b1, a1 * b1 * beta + a0 * b0
            { Fq6::add(18, 6) }
            // (a0 + a1) * (b0 + b1), a1 * b1 * beta + a0 * b0, a0 * b0 + a1 * b1
            { Fq6::sub(12, 0) }
            // a1 * b1 * beta + a0 * b0, (a0 + a1) * (b0 + b1) - (a0 * b0 + a1 * b1)
        }
    }

    // input:
    //   p   (12 elements)
    //   c0  (2 elements)
    //   c3  (2 elements)
    //   c4  (2 elements)
    pub fn mul_by_034() -> Script {
        script! {
            // copy p.c1, c3, c4
            { Fq6::copy(6) }
            { Fq2::copy(8) }
            { Fq2::copy(8) }

            // compute b = p.c1 * (c3, c4)
            { Fq6::mul_by_01() }

            // copy p.c0, c0
            { Fq6::copy(18) }
            { Fq2::copy(16) }
            { Fq6::mul_by_fp2() }

            // compute beta * b
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }

            // compute final c0 = a + beta * b
            { Fq6::copy(6) }
            { Fq6::add(6, 0) }

            // compute e = p.c0 + p.c1
            { Fq6::add(30, 24) }

            // compute c0 + c3
            { Fq2::add(28, 26) }

            // roll c4
            { Fq2::roll(26) }

            // update e = e * (c0 + c3, c4)
            { Fq6::mul_by_01() }

            // sum a and b
            { Fq6::add(18, 12) }

            // compute final c1 = e - (a + b)
            { Fq6::sub(6, 0) }
        }
    }

    // input:
    //   p   (12 elements)
    //   c0  (2 elements)
    //   c3  (2 elements)
    pub fn mul_by_034_with_4_constant(constant: &ark_bn254::Fq2) -> Script {
        script! {
            // copy p.c1, c3, c4
            { Fq6::copy(4) }
            { Fq2::copy(6) }

            // compute b = p.c1 * (c3, c4)
            { Fq6::mul_by_01_with_1_constant(constant) }
            // [p.c0, p.c1, c0, c3, b]

            // copy p.c0, c0
            { Fq6::copy(16) }
            { Fq2::copy(14) }

            // compute a = p.c0 * c0
            { Fq6::mul_by_fp2() }
            // [p.c0, p.c1, c0, c3, b, a]

            // compute beta * b
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }
            // [p.c0, p.c1, c0, c3, b, a, b * beta]

            // compute final c0 = a + beta * b
            { Fq6::copy(6) }
            { Fq6::add(6, 0) }
            // [p.c0, p.c1, c0, c3, b, a, a + b * beta]
            // [p.c0, p.c1, c0, c3, b, a, c0']

            // compute e = p.c0 + p.c1
            { Fq6::add(28, 22) }
            // [c0, c3, b, a, c0', e]

            // compute c0 + c3
            { Fq2::add(26, 24) }
            // [b, a, c0', e, c0 + c3]

            // update e = e * (c0 + c3, c4)
            { Fq6::mul_by_01_with_1_constant(constant) }
            // [b, a, c0', e * (c0 + c3, c4)]
            // [b, a, c0', e]

            // sum a and b
            { Fq6::add(18, 12) }
            // [c0', e, a + b]

            // compute final c1 = e - (a + b)
            { Fq6::sub(6, 0) }
            // [c0', e - a + b]
            // [c0', c1']
        }
    }

    // input:
    //   p   (12 elements)
    //   c3  (2 elements)
    //   c4  (2 elements)
    // where c0 is a trival value ONE, so we can ignore it
    pub fn mul_by_34() -> Script {
        script! {
            // copy p.c1, c3, c4
            { Fq6::copy(4) }
            { Fq2::copy(8) }
            { Fq2::copy(8) }
            // [p, c3, c4, p.c1, c3, c4]

            // compute b = p.c1 * (c3, c4)
            { Fq6::mul_by_01() }
            // [p, c3, c4, b]

            // a = p.c0 * c0, where c0 = 1
            { Fq6::copy(16) }
            // [p, c3, c4, b, a]

            // compute beta * b
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }
            // [p, c3, c4, b, a, beta * b]

            // compute final c0 = a + beta * b
            { Fq6::copy(6) }
            { Fq6::add(6, 0) }
            // [p, c3, c4, b, a, c0]

            // compute e = p.c0 + p.c1
            { Fq6::add(28, 22) }
            // [c3, c4, b, a, c0, e]

            // compute c0 + c3, where c0 = 1
            { Fq2::roll(26) }
            { Fq2::push_one() }
            { Fq2::add(2, 0) }
            // [c4, b, a, c0, e, 1 + c3]

            // update e = e * (c0 + c3, c4), where c0 = 1
            { Fq2::roll(26) }
            { Fq6::mul_by_01() }
            // [b, a, c0, e]

            // sum a and b
            { Fq6::add(18, 12) }
            // [c0, e, a + b]

            // compute final c1 = e - (a + b)
            { Fq6::sub(6, 0) }
        }
    }

    pub fn hinted_mul_by_34(p: ark_bn254::Fq12, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_mul_by_01(p.c1, c3, c4);
        let (hinted_script2, hint2) = Fq6::hinted_mul_by_01(p.c0+p.c1, c3+ark_bn254::Fq2::ONE, c4);

        let mut script = script! {};

        let script_lines = [
            // copy p.c1, c3, c4
            Fq6::copy(4),
            Fq2::copy(8),
            Fq2::copy(8),
            // [p, c3, c4, p.c1, c3, c4]

            // compute b = p.c1 * (c3, c4)
            hinted_script1,
            // [p, c3, c4, b]

            // a = p.c0 * c0, where c0 = 1
            Fq6::copy(16),
            // [p, c3, c4, b, a]

            // compute beta * b
            Fq6::copy(6),
            Fq12::mul_fq6_by_nonresidue(),
            // [p, c3, c4, b, a, beta * b]

            // compute final c0 = a + beta * b
            Fq6::copy(6),
            Fq6::add(6, 0),
            // [p, c3, c4, b, a, c0]

            // compute e = p.c0 + p.c1
            Fq6::add(28, 22),
            // [c3, c4, b, a, c0, e]

            // compute c0 + c3, where c0 = 1
            Fq2::roll(26),
            Fq2::push_one_not_montgomery(),
            Fq2::add(2, 0),
            // [c4, b, a, c0, e, 1 + c3]

            // update e = e * (c0 + c3, c4), where c0 = 1
            Fq2::roll(26),
            hinted_script2,
            // [b, a, c0, e]

            // sum a and b
            Fq6::add(18, 12),
            // [c0, e, a + b]

            // compute final c1 = e - (a + b)
            Fq6::sub(6, 0),
        ];

        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }
        hints.extend(hint1);
        hints.extend(hint2);

        (script, hints)
    }

    pub fn copy(a: u32) -> Script {
        script! {
            { Fq6::copy(a + 6) }
            { Fq6::copy(a + 6) }
        }
    }

    pub fn roll(a: u32) -> Script {
        script! {
            { Fq6::roll(a + 6) }
            { Fq6::roll(a + 6) }
        }
    }

    pub fn cyclotomic_square() -> Script {
        // https://eprint.iacr.org/2009/565.pdf
        // based on the implementation in arkworks-rs, fq12_2over3over2.rs

        let sqr = || {
            script! {
                // compute tmp = ra * rb
                { Fq2::copy(2) }
                { Fq2::copy(2) }
                { Fq2::mul(2, 0) }

                // compute ra + rb
                { Fq2::copy(4) }
                { Fq2::copy(4) }
                { Fq2::add(2, 0) }

                // compute ra + beta * rb
                { Fq2::roll(4) }
                { Fq6::mul_fq2_by_nonresidue() }
                { Fq2::roll(6) }
                { Fq2::add(2, 0) }

                // compute (ra + rb) * (ra + beta * rb) - tmp - tmp * beta
                { Fq2::mul(2, 0) }
                { Fq2::copy(2) }
                { Fq6::mul_fq2_by_nonresidue() }
                { Fq2::copy(4) }
                { Fq2::add(2, 0) }
                { Fq2::sub(2, 0) }
                { Fq2::double(2) }
            }
        };

        script! {
            // copy r0 = c0.c0 and r1 = c1.c1
            { Fq2::copy(10) }
            { Fq2::copy(4) }

            // compute t0 = r0^2 + r1^2 * beta, t1 = 2r0r1
            { sqr() }

            // copy r2 = c1.c0 and r3 = c0.c2
            { Fq2::copy(8) }
            { Fq2::copy(12) }

            // compute t2 = r2^2 + r3^2 * beta, t3 = 2r2r3
            { sqr() }

            // copy r4 = c0.c1 and r5 = c1.c2
            { Fq2::copy(16) }
            { Fq2::copy(10) }

            // compute t4 = r4^2 + r5^2 * beta, t5 = 242r5
            { sqr() }

            // z0 = 2 * (t0 - r0) + t0
            { Fq2::copy(10) }
            { Fq2::roll(24) }
            { Fq2::sub(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(12) }
            { Fq2::add(2, 0) }

            // z4 = 2 * (t2 - r4) + t2
            { Fq2::copy(8) }
            { Fq2::roll(22) }
            { Fq2::sub(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(10) }
            { Fq2::add(2, 0) }

            // z3 = 2 * (t4 - r3) + t4
            { Fq2::copy(6) }
            { Fq2::roll(20) }
            { Fq2::sub(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(8) }
            { Fq2::add(2, 0) }

            // z2 = 2 * (beta * t5 + r2) + (beta * t5)
            { Fq2::roll(6) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::copy(0) }
            { Fq2::roll(18) }
            { Fq2::add(2, 0) }
            { Fq2::double(0) }
            { Fq2::add(2, 0) }

            // z1 = 2 * (t1 + r1) + t1
            { Fq2::copy(10) }
            { Fq2::roll(16) }
            { Fq2::add(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(12) }
            { Fq2::add(2, 0) }

            // z5 = 2 * (t3 + r5) + t5
            { Fq2::copy(10) }
            { Fq2::roll(14) }
            { Fq2::add(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(12) }
            { Fq2::add(2, 0) }
        }
    }

    pub fn square() -> Script {
        script! {
            // v0 = c0 + c1
            { Fq6::copy(6) }
            { Fq6::copy(6) }
            { Fq6::add(6, 0) }

            // v3 = c0 + beta * c1
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }
            { Fq6::copy(18) }
            { Fq6::add(0, 6) }

            // v2 = c0 * c1
            { Fq6::mul(12, 18) }

            // v0 = v0 * v3
            { Fq6::mul(12, 6) }

            // final c0 = v0 - (beta + 1) * v2
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }
            { Fq6::copy(12) }
            { Fq6::add(6, 0) }
            { Fq6::sub(6, 0) }

            // final c1 = 2 * v2
            { Fq6::double(6) }
        }
    }

    pub fn hinted_square(a: ark_bn254::Fq12) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hints1) = Fq6::hinted_mul(12, a.c1, 18, a.c0);
        let mut beta_ac1 = a.c1;
        ark_bn254::Fq12Config::mul_fp6_by_nonresidue_in_place(&mut beta_ac1);
        let (hinted_script2, hints2) = Fq6::hinted_mul(12, a.c0 + a.c1, 6, a.c0 + beta_ac1);

        let mut script = script! {};

        let script_lines = [
            // v0 = c0 + c1
            Fq6::copy(6),
            Fq6::copy(6),
            Fq6::add(6, 0),

            // v3 = c0 + beta * c1
            Fq6::copy(6),
            Fq12::mul_fq6_by_nonresidue(),
            Fq6::copy(18),
            Fq6::add(0, 6),

            // v2 = c0 * c1
            hinted_script1,

            // v0 = v0 * v3
            hinted_script2,

            // final c0 = v0 - (beta + 1) * v2
            Fq6::copy(6),
            Fq12::mul_fq6_by_nonresidue(),
            Fq6::copy(12),
            Fq6::add(6, 0),
            Fq6::sub(6, 0),

            // final c1 = 2 * v2
            Fq6::double(6),
        ];

        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hints1);
        hints.extend(hints2);
        
        (script, hints)
    }

    pub fn cyclotomic_inverse() -> Script {
        script! {
            { Fq6::neg(0) }
        }
    }

    pub fn inv() -> Script {
        script! {
            // copy c1
            { Fq6::copy(0) }

            // compute beta * v1 = beta * c1^2
            { Fq6::square() }
            { Fq12::mul_fq6_by_nonresidue() }

            // copy c0
            { Fq6::copy(12) }

            // compute v0 = c0^2 + beta * v1
            { Fq6::square() }
            { Fq6::sub(0, 6) }

            // compute inv v0
            { Fq6::inv() }

            // dup inv v0
            { Fq6::copy(0) }

            // compute c0
            { Fq6::mul(18, 0) }

            // compute c1
            { Fq6::neg(12) }
            { Fq6::mul(12, 0) }
        }
    }

    pub fn frobenius_map(i: usize) -> Script {
        script! {
            { Fq6::roll(6) }
            { Fq6::frobenius_map(i) }
            { Fq6::roll(6) }
            { Fq6::frobenius_map(i) }
            { Fq6::mul_by_fp2_constant(&ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1[i % ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1.len()]) }
        }
    }

    pub fn hinted_frobenius_map(i: usize, a: ark_bn254::Fq12) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_frobenius_map(i, a.c0);
        let (hinted_script2, hint2) = Fq6::hinted_frobenius_map(i, a.c1);
        let (hinted_script3, hint3) = Fq6::hinted_mul_by_fp2_constant(a.c1.frobenius_map(i), &ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1[i % ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1.len()]);

        let mut script = script! {};
        let script_lines = [
            Fq6::roll(6),
            hinted_script1,
            Fq6::roll(6),
            hinted_script2,
            hinted_script3,
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);

        (script, hints)
    }

    pub fn toaltstack() -> Script {
        script! {
            { Fq6::toaltstack() }
            { Fq6::toaltstack() }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            { Fq6::fromaltstack() }
            { Fq6::fromaltstack() }
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fq6::drop() }
            { Fq6::drop() }
        }
    }

    pub fn cyclotomic_pow_by_r() -> Script {
        // idea: first compute mul_by_p, then handle the delta using double-and-add

        let mut delta = BigUint::from_str_radix(Fq::MODULUS, 16)
            .unwrap()
            .sub(BigUint::from_str_radix(Fr::MODULUS, 16).unwrap());

        let mut delta_bits = vec![];
        while !delta.is_zero() {
            delta_bits.push(delta.bit(0));
            delta.shr_assign(1);
        }

        let loop_no_script = script! {
            { Fq12::cyclotomic_square() }
        };

        let loop_yes_script = script! {
            { Fq12::cyclotomic_square() }
            { Fq12::copy(12) }
            { Fq12::mul(12, 0) }
        };

        script! {
            { Fq12::copy(0) }
            { Fq12::frobenius_map(1) }
            { Fq12::toaltstack() }
            { Fq12::copy(0) }

            for bit in delta_bits.iter().rev().skip(1) {
                if *bit {
                    { loop_yes_script.clone() }
                } else {
                    { loop_no_script.clone() }
                }
            }

            { Fq12::roll(12) }
            { Fq12::drop() }
            { Fq12::cyclotomic_inverse() }
            { Fq12::fromaltstack() }
            { Fq12::mul(12, 0) }
        }
    }

    pub fn move_to_cyclotomic() -> Script {
        script! {
            // compute f1 = a.cyclotomic_inverse()
            { Fq12::copy(0) }
            { Fq12::cyclotomic_inverse() }

            // compute f2 = a.inverse()
            { Fq12::roll(12) }
            { Fq12::inv() }

            // compute r := f1 * f2
            { Fq12::mul(12, 0) }

            // copy f2 := r, r
            { Fq12::copy(0) }

            // r.frobenius_map_in_place(2)
            { Fq12::frobenius_map(2) }

            // r *= f2
            { Fq12::mul(12, 0) }
        }
    }

    pub fn cyclotomic_verify_in_place() -> Script {
        script! {
            // check p^4 + 1 = p^2
            { Fq12::copy(0) }
            { Fq12::frobenius_map(4) }
            { Fq12::copy(12) }
            { Fq12::mul(12, 0) }
            { Fq12::copy(12) }
            { Fq12::frobenius_map(2) }
            { Fq12::equalverify() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq12::Fq12;
    use crate::bn254::utils::{fq12_push, fq12_push_not_montgomery, fq2_push, fq2_push_not_montgomery};
    use crate::{execute_script_without_stack_limit, treepp::*};
    use ark_ff::AdditiveGroup;
    use ark_ff::{CyclotomicMultSubgroup, Field};
    use ark_std::UniformRand;
    use bitcoin_scriptexec::ExecError;
    use core::ops::Mul;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    #[test]
    fn test_bn254_fq12_add() {
        println!("Fq12.add: {} bytes", Fq12::add(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fq12_push(a) }
                { fq12_push(b) }
                { Fq12::add(12, 0) }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_double() {
        println!("Fq12.double: {} bytes", Fq12::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fq12_push(a) }
                { Fq12::double(0) }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_mul() {
        println!("Fq12.mul: {} bytes", Fq12::mul(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let script = script! {
                { fq12_push(a) }
                { fq12_push(b) }
                { Fq12::mul(12, 0) }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_mul() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq12::hinted_mul(12, a, 0, b);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { fq12_push_not_montgomery(a) }
                { fq12_push_not_montgomery(b) }
                { hinted_mul.clone() }
                { fq12_push_not_montgomery(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let res = execute_script_without_stack_limit(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!("Fq6::window_mul: {} @ {} stack", hinted_mul.len(), max_stack);
        }

    }

    #[test]
    fn test_bn254_fq12_hinted_mul_by_34() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::ONE;
            let c3 = ark_bn254::Fq2::rand(&mut prng);
            let c4 = ark_bn254::Fq2::rand(&mut prng);
            let mut b = a;
            b.mul_by_034(&c0, &c3, &c4);
            let (hinted_mul, hints) = Fq12::hinted_mul_by_34(a, c3, c4);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { fq12_push_not_montgomery(a) }
                { fq2_push_not_montgomery(c3) }
                { fq2_push_not_montgomery(c4) }
                { hinted_mul.clone() }
                { fq12_push_not_montgomery(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!("Fq6::window_mul: {} @ {} stack", hinted_mul.len(), max_stack);
        }

    }

    #[test]
    fn test_bn254_fq12_mul_cpt() {
        println!("Fq12.mul_cpt: {} bytes", Fq12::mul_cpt(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let script = script! {
                { fq12_push(a) }
                { fq12_push(b) }
                { Fq12::mul_cpt(12, 0) }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_cyclotomic_square() {
        println!(
            "Fq12.cyclotomic_square: {} bytes",
            Fq12::cyclotomic_square().len()
        );
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c = a.cyclotomic_square();

            let script = script! {
                { fq12_push(a) }
                { Fq12::cyclotomic_square() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_square() {
        println!("Fq12.square: {} bytes", Fq12::square().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c = a.square();

            let script = script! {
                { fq12_push(a) }
                { Fq12::square() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = a.square();

            let (hinted_square, hints) = Fq12::hinted_square(a);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { fq12_push_not_montgomery(a) }
                { hinted_square.clone() }
                { fq12_push_not_montgomery(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
            println!("Fq12::hinted_square: {} @ {} stack", hinted_square.len(), max_stack);
        }
    }


    #[test]
    fn test_bn254_fq12_mul_by_034() {
        println!("Fq12.mul_by_034: {} bytes", Fq12::mul_by_034().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::rand(&mut prng);
            let c3 = ark_bn254::Fq2::rand(&mut prng);
            let c4 = ark_bn254::Fq2::rand(&mut prng);
            let mut b = a;
            b.mul_by_034(&c0, &c3, &c4);

            let script = script! {
                { fq12_push(a) }
                { fq2_push(c0) }
                { fq2_push(c3) }
                { fq2_push(c4) }
                { Fq12::mul_by_034() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_mul_by_34() {
        println!("Fq12.mul_by_034: {} bytes", Fq12::mul_by_034().len());
        println!("Fq12.mul_by_34: {} bytes", Fq12::mul_by_34().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::ONE;
            let c3 = ark_bn254::Fq2::rand(&mut prng);
            let c4 = ark_bn254::Fq2::rand(&mut prng);
            let mut b = a;
            b.mul_by_034(&c0, &c3, &c4);

            let script = script! {
                { fq12_push(a) }
                { fq2_push(c3) }
                { fq2_push(c4) }
                { Fq12::mul_by_34() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_inv() {
        println!("Fq12.inv: {} bytes", Fq12::inv().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = a.inverse().unwrap();

            let script = script! {
                { fq12_push(a) }
                { Fq12::inv() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_frobenius_map() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            for i in 0..12 {
                let a = ark_bn254::Fq12::rand(&mut prng);
                let b = a.frobenius_map(i);

                let frobenius_map = Fq12::frobenius_map(i);
                println!("Fq12.frobenius_map({}): {} bytes", i, frobenius_map.len());

                let script = script! {
                    { fq12_push(a) }
                    { frobenius_map.clone() }
                    { fq12_push(b) }
                    { Fq12::equalverify() }
                    OP_TRUE
                };
            run(script);
            }
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_frobenius_map() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            for i in 0..12 {
                let a = ark_bn254::Fq12::rand(&mut prng);
                let b = a.frobenius_map(i);

                let (hinted_frobenius_map, hints) = Fq12::hinted_frobenius_map(i, a);
                println!("Fq12.hinted_frobenius_map({}): {} bytes", i, hinted_frobenius_map.len());

                let script = script! {
                    for hint in hints { 
                        { hint.push() }
                    }
                    { fq12_push_not_montgomery(a) }
                    { hinted_frobenius_map.clone() }
                    { fq12_push_not_montgomery(b) }
                    { Fq12::equalverify() }
                    OP_TRUE
                };
                let exec_result = execute_script(script);
                assert!(exec_result.success);
            }
        }
    }

    #[test]
    fn test_bn254_fq12_mul_by_r() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let cyclotomic_pow_by_r = Fq12::cyclotomic_pow_by_r();
        println!(
            "Fq12.cyclotomic_pow_by_r: {} bytes",
            cyclotomic_pow_by_r.len()
        );

        for _ in 0..1 {
            let a = ark_bn254::fq12::Fq12::rand(&mut prng);

            // move a into the cyclotomic subgroup
            let a = {
                let f1 = a.cyclotomic_inverse().unwrap();

                let mut f2 = a.inverse().unwrap();
                let mut r = f1.mul(&f2);
                f2 = r;

                r.frobenius_map_in_place(2);

                r *= f2;
                r
            };

            let res = a.cyclotomic_exp(
                BigUint::from_str(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
                )
                .unwrap()
                .to_u64_digits(),
            );

            let script = script! {
                { fq12_push(a) }
                { cyclotomic_pow_by_r.clone() }
                { fq12_push(res) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_move_to_cyclotomic() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let move_to_cyclotomic = Fq12::move_to_cyclotomic();
        println!(
            "Fq12.move_to_cyclotomic: {} bytes",
            move_to_cyclotomic.len()
        );

        for _ in 0..1 {
            let a = ark_bn254::fq12::Fq12::rand(&mut prng);

            // move a into the cyclotomic subgroup
            let res = {
                let f1 = a.cyclotomic_inverse().unwrap();

                let mut f2 = a.inverse().unwrap();
                let mut r = f1.mul(&f2);
                f2 = r;

                r.frobenius_map_in_place(2);

                r *= f2;
                r
            };

            let script = script! {
                { fq12_push(a) }
                { move_to_cyclotomic.clone() }
                { fq12_push(res) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_cyclotomic_verify_in_place() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let cyclotomic_verify_in_place = Fq12::cyclotomic_verify_in_place();
        println!(
            "Fq12.cyclotomic_verify_in_place: {} bytes",
            cyclotomic_verify_in_place.len()
        );

        for _ in 0..1 {
            let a = ark_bn254::fq12::Fq12::rand(&mut prng);

            // move a into the cyclotomic subgroup
            let res = {
                let f1 = a.cyclotomic_inverse().unwrap();

                let mut f2 = a.inverse().unwrap();
                let mut r = f1.mul(&f2);
                f2 = r;

                r.frobenius_map_in_place(2);

                r *= f2;
                r
            };

            let script = script! {
                { fq12_push(a) }
                { cyclotomic_verify_in_place.clone() }
                { Fq12::drop() }
            };
            let exec_result = execute_script(script);
            assert_eq!(exec_result.error, Some(ExecError::EqualVerify));

            let script = script! {
                { fq12_push(res) }
                { cyclotomic_verify_in_place.clone() }
                { Fq12::drop() }
                OP_TRUE
            };
            run(script);
        }
    }
}
