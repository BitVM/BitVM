// utils for push fields into stack
use crate::bn254::fq2::Fq2;
use ark_ec::AffineRepr;
use ark_ff::Field;
use num_bigint::BigUint;

use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};

/// input of func (params):
///      p.x, p.y
/// output on stack:
///      x' = -p.x / p.y
///      y' = 1 / p.y
pub fn from_eval_point(p: ark_bn254::G1Affine) -> Script {
    let py_inv = p.y().unwrap().inverse().unwrap();
    script! {
        { Fq::push_u32_le(&BigUint::from(py_inv).to_u32_digits()) }
        // check p.y.inv() is valid
        { Fq::copy(0) }
        { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
        { Fq::mul() }
        { Fq::push_one() }
        { Fq::equalverify(1, 0) }

        // -p.x / p.y
        { Fq::copy(0) }
        { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
        { Fq::neg(0) }
        { Fq::mul() }
        { Fq::roll(1) }
    }
}

pub fn fq2_push(element: ark_bn254::Fq2) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
    }
}

pub fn fq6_push(element: ark_bn254::Fq6) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

pub fn fq12_push(element: ark_bn254::Fq12) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

/// add two points T and Q
///     x' = alpha^2 - T.x - Q.x
///     y' = -bias - alpha * x'
///
/// input on stack:
///     T.x (2 elements)
///     Q.x (2 elements)
///
/// output on stack:
///     T'.x (2 elements)
///     T'.y (2 elements)
pub fn affine_add_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        { Fq2::neg(0) }
        { Fq2::roll(2) }
        { Fq2::neg(0) }
        { Fq2::add(2, 0) }
        // [-T.x - Q.x]
        { fq2_push(c3) }
        { Fq2::copy(0) }
        { Fq2::square() }
        // [-T.x - Q.x, alpha, alpha^2]
        { Fq2::add(4, 0) }
        { Fq2::copy(0) }
        // [alpha, x', x']
        { Fq2::mul(4, 0) }
        { Fq2::neg(0) }
        // [x', -alpha * x']
        { fq2_push(c4) }
        { Fq2::add(2, 0) }
        // [x', y']
    }
}

/// double a point T:
///     x' = alpha^2 - 2 * T.x
///     y' = -bias - alpha* x'
///
/// input on stack:
///     T.x (2 elements)
///
/// output on stack:
///     T'.x (2 elements)
///     T'.y (2 elements)
pub fn affine_double_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        { Fq2::double(0) }
        { Fq2::neg(0) }
        // [- 2 * T.x]
        { fq2_push(c3) }
        { Fq2::copy(0) }
        { Fq2::square() }
        // [- 2 * T.x, alpha, alpha^2]
        { Fq2::add(4, 0) }
        { Fq2::copy(0) }
        // [alpha, x', x']
        { Fq2::mul(4, 0) }
        { Fq2::neg(0) }
        // [x', -alpha * x']

        { fq2_push(c4) }
        { Fq2::add(2, 0) }
        // [x', y']
    }
}

/// check line through one point, that is:
///     y - alpha * x - bias = 0
///
/// input on stack:
///     x (2 elements)
///     y (2 elements)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
///
/// output:
///     true or false (consumed on stack)
pub fn check_line_through_point(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        { Fq2::roll(2) }
        { Fq2::mul_by_constant(&c3) }
        { Fq2::neg(0) }
        { Fq2::add(2, 0) }
        // [y - alpha * x]

        { fq2_push(c4) }
        { Fq2::add(2, 0) }
        // [y - alpha * x - bias]

        { Fq2::push_zero() }
        { Fq2::equalverify() }
    }
}

/// check whether a tuple coefficient (alpha, -bias) of a tangent line is satisfied with expected point T (affine)
/// two aspects:
///     1. alpha * (2 * T.y) = 3 * T.x^2, make sure the alpha is the right ONE
///     2. T.y - alpha * T.x - bias = 0, make sure the -bias is the right ONE
///
/// input on stack:
///     T.x (2 element)
///     T.y (2 element)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
///
/// output:
///     true or false (consumed on stack)
pub fn check_tangent_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // alpha * (2 * T.y) = 3 * T.x^2
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::mul_by_constant(&c3) }
        // [T.x, T.y, alpha * (2 * T.y)]
        { Fq2::copy(4) }
        { Fq2::square() }
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::add(2, 0) }
        // [T.x, T.y, alpha * (2 * T.y), 3 * T.x^2]
        { Fq2::neg(0) }
        { Fq2::add(2, 0) }
        { Fq2::push_zero() }
        { Fq2::equalverify() }
        // [T.x, T.y]

        // check: T.y - alpha * T.x - bias = 0
        { check_line_through_point(c3, c4) }
        // []
    }
}

/// check whether a tuple coefficient (alpha, -bias) of a chord line is satisfied with expected points T and Q (both are affine cooordinates)
/// two aspects:
///     1. T.y - alpha * T.x - bias = 0
///     2. Q.y - alpha * Q.x - bias = 0, make sure the alpha/-bias are the right ONEs
///
/// input on stack:
///     T.x (2 elements)
///     T.y (2 elements)
///     Q.x (2 elements)
///     Q.y (2 elements)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
/// output:
///     true or false (consumed on stack)
pub fn check_chord_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // check: Q.y - alpha * Q.x - bias = 0
        { check_line_through_point(c3, c4) }
        // [T.x, T.y]
        // check: T.y - alpha * T.x - bias = 0
        { check_line_through_point(c3, c4) }
        // []
    }
}

// stack data: beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B,
// P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Qx, Qy
// [..., Fq12, Fq12, Fq12, Fq12, Fq, Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq)]
//
// flag == true ? T + Q : T - Q
pub fn add_line_with_flag(flag: bool) -> Script {
    script! {
    // let theta = self.y - &(q.y * &self.z);
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy
    { Fq2::copy(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy
    if !flag {
        { Fq2::neg(0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, -Qy
    }
    { Fq2::copy(8) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy, Tz
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy * Tz
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty - Qy * Tz

    // let lambda = self.x - &(q.x * &self.z);
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta
    { Fq2::copy(10) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx
    { Fq2::copy(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx
    { Fq2::copy(10) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx, Tz
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx * Tz
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx - Qx * Tz

    // let c = theta.square();
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, theta
    { Fq2::square() }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, theta^2

    // let d = lambda.square();
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, lambda
    { Fq2::square() }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, lambda^2

    // let e = lambda * &d;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d
    { Fq2::copy(4) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda, d
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda * d

    // let f = self.z * &c;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e
    { Fq2::copy(14) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e, Tz
    { Fq2::roll(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, Tz, c
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, Tz * c

    // let g = self.x * &d;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, ff
    { Fq2::roll(18) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, d, e, ff, Tx
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, Tx, d
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, Tx * d

    // let h = e + &f - &g.double();
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g
    { Fq2::copy(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, g
    { Fq2::neg(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, -g
    { Fq2::double(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, -2g
    { Fq2::roll(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g, ff
    { Fq2::add(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff
    { Fq2::copy(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff, e
    { Fq2::add(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff + e

    // self.x = lambda * &h;
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h
    { Fq2::copy(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h
    { Fq2::copy(8) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h, lambda
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h * lambda

    // self.y = theta * &(g - &h) - &(e * &self.y);
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x
    { Fq2::copy(10) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x, theta
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, h, x, theta, g
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta, g, h
    { Fq2::sub(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta, g - h
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h)
    { Fq2::copy(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e
    { Fq2::roll(18) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e, Ty
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e * Ty
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h) - e * Ty

    // self.z *= &e;
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, y
    { Fq2::roll(14) }
    // f, Px, Py, Qx, Qy, theta, lambda, e, x, y, Tz
    { Fq2::roll(6) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, Tz, e
    { Fq2::mul(2, 0) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, Tz * e

    // let j = theta * &q.x - &(lambda * &q.y);
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, z
    { Fq2::copy(8) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, z, theta
    { Fq2::roll(14) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta, Qx
    { Fq2::mul(2, 0) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta * Qx
    { Fq2::copy(8) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta * Qx, lambda
    { Fq2::roll(14) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda, Qy
    if !flag {
        { Fq2::neg(0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda, -Qy
    }
    { Fq2::mul(2, 0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda * Qy
    { Fq2::sub(2, 0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx - lambda * Qy

    // (lambda, -theta, j)
    // f, Px, Py, theta, lambda, x, y, z, j
    { Fq2::roll(8) }
    // f, Px, Py, theta, x, y, z, j, lambda
    { Fq2::roll(10) }
    // f, Px, Py, x, y, z, j, lambda, theta
    { Fq2::neg(0) }
    // f, Px, Py, x, y, z, j, lambda, -theta
    { Fq2::roll(4) }
    // f, Px, Py, x, y, z, lambda, -theta, j

    }
}

// script of double line for the purpose of non-fixed point in miller loop
// stack data: beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B,
// P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz
// [..., Fq12, Fq12, Fq12, Fq12, Fq, Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq)]
pub fn double_line() -> Script {
    script! {

    // let mut a = self.x * &self.y;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx, Ty
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx * Ty

    // a.mul_assign_by_fp(two_inv);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a
    { Fq::copy(72) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, 1/2
    { Fq2::mul_by_fq(1, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a * 1/2

    // let b = self.y.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, Ty
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, Ty^2

    // let c = self.z.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, Tz
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, Tz^2

    // let e = ark_bn254::g2::Config::COEFF_B * &(c.double() + &c);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c
    { Fq2::copy(0) }
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, c, c
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, c, 2 * c
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c
    { Fq2::copy(76) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c, B
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c * B

    // let f = e.double() + &e;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e
    { Fq2::copy(0) }
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, e, e
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, e, 2 * e
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, 3 * e

    // let mut g = b + &f;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f
    { Fq2::copy(8) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f, b
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f + b

    // g.mul_assign_by_fp(two_inv);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g
    { Fq::copy(82) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g, 1/2
    { Fq2::mul_by_fq(1, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g * 1/2

    // let h = (self.y + &self.z).square() - &(b + &c);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Tz, a, b, c, e, f, g, Ty
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, Ty, Tz
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, Ty + Tz
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, (Ty + Tz)^2
    { Fq2::copy(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, (Ty + Tz)^2, b
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2, b, c
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2, b + c
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2 - (b + c)

    // let i = e - &b;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h
    { Fq2::copy(6) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e
    { Fq2::copy(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e, b
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e - b

    // let j = self.x.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, i
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, Tx
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, Tx^2

    // let e_square = e.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, j
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e^2

    // self.x = a * &(b - &f);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e^2
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, f, g, h, i, j, e^2, a
    { Fq2::copy(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, f, g, h, i, j, e^2, a, b
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a, b, f
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a, b - f
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a * (b - f)

    // self.y = g.square() - &(e_square.double() + &e_square);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, x
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, e^2, x, g
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, e^2, x, g^2
    { Fq2::roll(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2, e^2
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2, 2 * e^2
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, 3 * e^2
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2 - 3 * e^2

    // self.z = b * &h;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, y
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, h, i, j, x, y, b
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, b, h
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, b, h, h
    { Fq2::mul(4, 2) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, h, z

    // (-h, j.double() + &j, i)
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, h, z
    { Fq2::roll(2) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, z, h
    { Fq2::neg(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, z, -h
    { Fq2::roll(8) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j, j
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j, 2 * j
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, 3 * j
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, x, y, z, -h, 3 * j, i

    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::{test_rng, UniformRand};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_from_eval_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let script = script! {
            { from_eval_point(p) }
            { Fq::push_u32_le(&BigUint::from(-p.x / p.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p.y.inverse().unwrap()).to_u32_digits()) }
            { Fq::equalverify(2, 0) }
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
