// Rephrased from https://github.com/arkworks-rs/algebra/blob/master/ec/src/models/bn/g2.rs#L185
// Cannot directly obtain G2 because of visibility

use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::{fq::Fq, fq2::Fq2};
use crate::treepp::{pushable, script, Script};
use ark_ec::bn::{BnConfig, TwistType};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use num_traits::One;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G2Prepared {
    /// Stores the coefficients of the line evaluations as calculated in
    /// <https://eprint.iacr.org/2013/722.pdf>
    pub ell_coeffs: Vec<EllCoeff>,
}

pub type EllCoeff = (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2);

#[derive(Clone, Copy, Debug)]
pub struct G2HomProjective {
    x: ark_bn254::Fq2,
    y: ark_bn254::Fq2,
    z: ark_bn254::Fq2,
}

impl G2HomProjective {
    // stack data: [1/2, B, Tx, Ty, Tz, Qx, Qy]
    // [Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq)]
    pub fn add_line() -> Script {
        script! {
        // let theta = self.y - &(q.y * &self.z);
        // [1/2, B, Tx, Ty, Tz, Qx, Qy, theta]
        { Fq2::copy(6) }
        { Fq2::copy(2) }
        { Fq2::copy(8) }
        { Fq2::mul(2, 0) }
        { Fq2::sub(2, 0) }

        // let lambda = self.x - &(q.x * &self.z);
        // [1/2, B, Tx, Ty, Tz, Qx, Qy, theta, lambda]
        { Fq2::copy(10) }
        { Fq2::copy(6) }
        { Fq2::copy(10) }
        { Fq2::mul(2, 0) }
        { Fq2::sub(2, 0) }

        // let c = theta.square();
        // [1/2, B, Tx, Ty, Tz, Qx, Qy, theta, lambda, c]
        { Fq2::copy(2) }
        { Fq2::square() }

        // let d = lambda.square();
        // [1/2, B, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d]
        { Fq2::copy(2) }
        { Fq2::square() }

        // let e = lambda * &d;
        // [1/2, B, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e]
        { Fq2::copy(4) }
        { Fq2::copy(2) }
        { Fq2::mul(2, 0) }

        // let f = self.z * &c;
        // [1/2, B, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, f]
        { Fq2::copy(14) }
        { Fq2::roll(6) }
        { Fq2::mul(2, 0) }

        // let g = self.x * &d;
        // [1/2, B, Ty, Tz, Qx, Qy, theta, lambda, e, f, g]
        { Fq2::roll(18) }
        { Fq2::roll(6) }
        { Fq2::mul(2, 0) }

        // let h = e + &f - &g.double();
        // [1/2, B, Ty, Tz, Qx, Qy, theta, lambda, e, g, h]
        { Fq2::copy(0) }
        { Fq2::neg(0) }
        { Fq2::double(0) }
        { Fq2::roll(4) }
        { Fq2::add(2, 0) }
        { Fq2::copy(4) }
        { Fq2::add(2, 0) }

        // self.x = lambda * &h;
        // [1/2, B, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x]
        { Fq2::copy(0) }
        { Fq2::copy(6) }
        { Fq2::mul(2, 0) }

        // self.y = theta * &(g - &h) - &(e * &self.y);
        // [1/2, B, Tz, Qx, Qy, theta, lambda, e, x, y]
        { Fq2::copy(10) }
        { Fq2::roll(6) }
        { Fq2::roll(6) }
        { Fq2::sub(2, 0) }
        { Fq2::mul(2, 0) }
        { Fq2::copy(4) }
        { Fq2::roll(16) }
        { Fq2::mul(2, 0) }
        { Fq2::sub(2, 0) }

        // self.z *= &e;
        // [1/2, B, Qx, Qy, theta, lambda, x, y, z]
        { Fq2::roll(14) }
        { Fq2::roll(6) }
        { Fq2::mul(2, 0) }

        // let j = theta * &q.x - &(lambda * &q.y);
        // [1/2, B, Qx, Qy, theta, lambda, x, y, z, j]
        { Fq2::copy(8) }
        { Fq2::copy(14) }
        { Fq2::mul(2, 0) }
        { Fq2::copy(8) }
        { Fq2::copy(14) }
        { Fq2::mul(2, 0) }
        { Fq2::sub(2, 0) }

        // (lambda, -theta, j)
        // [1/2, B, Qx, Qy, x, y, z, lambda, -theta, j]
        { Fq2::roll(8) }
        { Fq2::roll(10) }
        { Fq2::neg(0) }
        { Fq2::roll(4) }

        }
    }

    // stack data: [1/2, B, Qx, Qy, Qz]
    // [Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq)]
    pub fn double_line() -> Script {
        script! {

        // let mut a = self.x * &self.y;
        // stack data: [1/2, B, Qx, Qy, Qz, a]
        { Fq2::copy(4) }
        { Fq2::copy(4) }
        { Fq2::mul(2, 0) }

        // a.mul_assign_by_fp(two_inv);
        // stack data: [1/2, B, Qx, Qy, Qz, a]
        { Fq::copy(10) }
        { Fq2::mul_by_fq(1, 0) }

        // let b = self.y.square();
        // stack data: [1/2, B, Qx, Qy, Qz, a, b | b]
        { Fq2::copy(4) }
        { Fq2::square() }
        { Fq2::copy(0) }
        { Fq2::toaltstack() }

        // let c = self.z.square();
        // stack data: [1/2, B, Qx, Qy, Qz, a, b, c | b, c]
        { Fq2::copy(4) }
        { Fq2::square() }
        { Fq2::copy(0) }
        { Fq2::toaltstack() }

        // let e = ark_bn254::g2::Config::COEFF_B * &(c.double() + &c);
        // stack data: [1/2, B, Qx, Qy, Qz, a, b, e | b, c, e]
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::add(2, 0) }
        { Fq2::copy(12) }
        { Fq2::mul(2, 0) }
        { Fq2::copy(0) }
        { Fq2::toaltstack() }

        // let f = e.double() + &e;
        // stack data: [1/2, B, Qx, Qy, Qz, a, b, f | b, c, e]
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::add(2, 0) }

        // let mut g = b + &f;
        // stack data: [1/2, B, Qx, Qy, Qz, a, f, g | b, c, e]
        { Fq2::copy(0) }
        { Fq2::roll(4) }
        { Fq2::add(2, 0) }

        // g.mul_assign_by_fp(two_inv);
        // stack data: [1/2, B, Qx, Qy, Qz, a, f, g | b, c, e]
        { Fq2::copy(14) }
        { Fq2::mul_by_fq(1, 0) }

        // let h = (self.y + &self.z).square() - &(b + &c);
        // stack data: [1/2, B, Qx, a, f, g, e, b, h]
        { Fq2::roll(8) }
        { Fq2::roll(8) }
        { Fq2::add(2, 0) }
        { Fq2::square() }
        { Fq2::fromaltstack() }
        { Fq2::fromaltstack() }
        { Fq2::fromaltstack() }
        { Fq2::copy(0) }
        { Fq2::roll(4) }
        { Fq2::add(2, 0) }
        { Fq2::roll(6) }
        { Fq2::sub(0, 2) }

        // let i = e - &b;
        // stack data: [1/2, B, Qx, a, f, g, e, b, h, i]
        { Fq2::copy(4) }
        { Fq2::copy(4) }
        { Fq2::sub(2, 0) }

        // let j = self.x.square();
        // stack data: [1/2, B, a, f, g, e, b, h, i, j]
        { Fq2::roll(14) }
        { Fq2::square() }

        // let e_square = e.square();
        // stack data: [1/2, B, a, f, g, b, h, i, j, e^2]
        { Fq2::roll(8) }
        { Fq2::square() }

        // self.x = a * &(b - &f);
        // stack data: [1/2, B, g, b, h, i, j, e^2, x]
        { Fq2::copy(8) }
        { Fq2::roll(14) }
        { Fq2::sub(2, 0) }
        { Fq2::roll(14) }
        { Fq2::mul(2, 0) }

        // self.y = g.square() - &(e_square.double() + &e_square);
        // stack data: [1/2, B, b, h, i, j, x, y]
        { Fq2::roll(12) }
        { Fq2::square() }
        { Fq2::roll(4) }
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::add(2, 0) }

        // self.z = b * &h;
        // stack data: [1/2, B, h, i, j, x, y, z]
        { Fq2::roll(10) }
        { Fq2::copy(10) }
        { Fq2::mul(2, 0) }

        }
    }

    fn double_in_place(&mut self, two_inv: &ark_bn254::Fq) -> EllCoeff {
        // Formula for line function when working with
        // homogeneous projective coordinates.

        let mut a = self.x * &self.y;
        a.mul_assign_by_fp(two_inv);
        let b = self.y.square();
        let c = self.z.square();
        let e = ark_bn254::g2::Config::COEFF_B * &(c.double() + &c);
        let f = e.double() + &e;
        let mut g = b + &f;
        g.mul_assign_by_fp(two_inv);
        let h = (self.y + &self.z).square() - &(b + &c);
        let i = e - &b;
        let j = self.x.square();
        let e_square = e.square();

        self.x = a * &(b - &f);
        self.y = g.square() - &(e_square.double() + &e_square);
        self.z = b * &h;
        match ark_bn254::Config::TWIST_TYPE {
            TwistType::M => (i, j.double() + &j, -h),
            TwistType::D => (-h, j.double() + &j, i),
        }
        // (-h, j.double() + &j, i)
    }

    fn add_in_place(&mut self, q: &ark_bn254::G2Affine) -> EllCoeff {
        // Formula for line function when working with
        // homogeneous projective coordinates.
        let theta = self.y - &(q.y * &self.z);
        let lambda = self.x - &(q.x * &self.z);
        let c = theta.square();
        let d = lambda.square();
        let e = lambda * &d;
        let f = self.z * &c;
        let g = self.x * &d;
        let h = e + &f - &g.double();
        self.x = lambda * &h;
        self.y = theta * &(g - &h) - &(e * &self.y);
        self.z *= &e;
        let j = theta * &q.x - &(lambda * &q.y);

        // match ark_bn254::Config::TWIST_TYPE {
        //     TwistType::M => (j, -theta, lambda),
        //     TwistType::D => (lambda, -theta, j),
        // }
        (lambda, -theta, j)
    }
}

impl Default for G2Prepared {
    fn default() -> Self { Self::from(ark_bn254::G2Affine::generator()) }
}

impl From<ark_bn254::G2Affine> for G2Prepared {
    fn from(q: ark_bn254::G2Affine) -> Self {
        assert!(!q.infinity);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let mut ell_coeffs = vec![];
        let mut r = G2HomProjective {
            x: q.x,
            y: q.y,
            z: ark_bn254::Fq2::one(),
        };

        let neg_q = -q;

        for bit in ark_bn254::Config::ATE_LOOP_COUNT.iter().rev().skip(1) {
            ell_coeffs.push(r.double_in_place(&two_inv));

            match bit {
                1 => ell_coeffs.push(r.add_in_place(&q)),
                -1 => ell_coeffs.push(r.add_in_place(&neg_q)),
                _ => continue,
            }
        }

        let q1 = mul_by_char(q);
        let mut q2 = mul_by_char(q1);

        q2.y = -q2.y;

        ell_coeffs.push(r.add_in_place(&q1));
        ell_coeffs.push(r.add_in_place(&q2));

        Self { ell_coeffs }
    }
}

impl From<ark_bn254::G2Projective> for G2Prepared {
    fn from(q: ark_bn254::G2Projective) -> Self { q.into_affine().into() }
}

impl<'a> From<&'a ark_bn254::G2Affine> for G2Prepared {
    fn from(other: &'a ark_bn254::G2Affine) -> Self { (*other).into() }
}

impl<'a> From<&'a ark_bn254::G2Projective> for G2Prepared {
    fn from(q: &'a ark_bn254::G2Projective) -> Self { q.into_affine().into() }
}

fn mul_by_char(r: ark_bn254::G2Affine) -> ark_bn254::G2Affine {
    // multiply by field characteristic

    let mut s = r;
    s.x.frobenius_map_in_place(1);
    s.x *= &ark_bn254::Config::TWIST_MUL_BY_Q_X;
    s.y.frobenius_map_in_place(1);
    s.y *= &ark_bn254::Config::TWIST_MUL_BY_Q_Y;

    s
}
