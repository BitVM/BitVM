#![allow(non_snake_case)]
use crate::bn254::ell_coeffs::{EllCoeff, G2Prepared};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::treepp::*;
use ark_ec::bn::BnConfig;

pub struct Pairing;

impl Pairing {
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

    // input:
    //  f            12 elements
    //  coeffs.c0    2 elements
    //  coeffs.c1    2 elements
    //  coeffs.c2    2 elements
    //  p.x          1 element
    //  p.y          1 element
    //
    // output:
    //  new f        12 elements
    pub fn ell() -> Script {
        script! {
            // compute the new c0
            { Fq2::mul_by_fq(6, 0) }

            // compute the new c1
            { Fq2::mul_by_fq(5, 2) }

            // roll c2
            { Fq2::roll(4) }

            // compute the new f
            { Fq12::mul_by_034() }
        }
    }

    // input:
    //  f            12 elements
    //  p.x          1 element
    //  p.y          1 element
    //
    // output:
    //  new f        12 elements
    pub fn ell_by_constant(constant: &EllCoeff) -> Script {
        script! {
            // [f, px, py]
            // compute the new c0
            // [f, px, py, py]
            { Fq::copy(0) }
            // [f, px, py, py * q1.x1]
            { Fq::mul_by_constant(&constant.0.c0) }
            // [f, px, py * q1.x1, py]
            { Fq::roll(1) }
            // [f, px, py * q1.x1, py * q1.x2]
            { Fq::mul_by_constant(&constant.0.c1) }

            // compute the new c1
            // [f, px, py * q1.x1, py * q1.x2, px]
            { Fq::copy(2) }
            // [f, px, py * q1.x1, py * q1.x2, px * q1.y1]
            { Fq::mul_by_constant(&constant.1.c0) }
            // [f, py * q1.x1, py * q1.x2, px * q1.y1, px]
            { Fq::roll(3) }
            // [f, py * q1.x1, py * q1.x2, px * q1.y1, px * q1.y2]
            { Fq::mul_by_constant(&constant.1.c1) }

            // compute the new f
            // [f, py * q1.x1, py * q1.x2, px * q1.y1, px * q1.y2]
            { Fq12::mul_by_034_with_4_constant(&constant.2) }
        }
    }

    // input:
    //   p.x
    //   p.y
    pub fn miller_loop(constant: &G2Prepared) -> Script {
        let mut constant_iter = constant.ell_coeffs.iter();

        let script = script! {
            { Fq12::push_one() }

            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    { Fq12::square() }
                }

                { Fq2::copy(12) }
                { Pairing::ell_by_constant(constant_iter.next().unwrap()) }

                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq2::copy(12) }
                    { Pairing::ell_by_constant(constant_iter.next().unwrap()) }
                }
            }
            { Fq2::copy(12) }
            { Pairing::ell_by_constant(constant_iter.next().unwrap()) }
            { Fq2::roll(12) }
            { Pairing::ell_by_constant(constant_iter.next().unwrap()) }
        };
        assert_eq!(constant_iter.next(), None);
        script
    }

    // input:
    //   p.x
    //   p.y
    //   q.x
    //   q.y
    pub fn dual_miller_loop(constant_1: &G2Prepared, constant_2: &G2Prepared) -> Script {
        let mut constant_1_iter = constant_1.ell_coeffs.iter();
        let mut constant_2_iter = constant_2.ell_coeffs.iter();

        let script = script! {
            { Fq12::push_one() }

            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    { Fq12::square() }
                }

                { Fq2::copy(14) }
                { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }

                { Fq2::copy(12) }
                { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }

                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq2::copy(14) }
                    { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }

                    { Fq2::copy(12) }
                    { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }
                }
            }

            { Fq2::copy(14) }
            { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }

            { Fq2::copy(12) }
            { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }

            { Fq2::roll(14) }
            { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }

            { Fq2::roll(12) }
            { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }
        };

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        script
    }

    // input on stack (non-fixed) : [P1, P2, c, c_inv, wi]
    // input outside (fixed): L1(Q1), L2(Q2)
    pub fn dual_miller_loop_with_c_wi(constant_1: &G2Prepared, constant_2: &G2Prepared) -> Script {
        let mut constant_1_iter = constant_1.ell_coeffs.iter();
        let mut constant_2_iter = constant_2.ell_coeffs.iter();

        let script = script! {
            // f = c_inv
            { Fq12::copy(12) }

            // miller loop part, 6x + 2
            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                // update f (double), f = f * f
                { Fq12::square() }

                // update c_inv
                // f = f * c_inv, if digit == 1
                // f = f * c, if digit == -1
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
                    { Fq12::copy(24) }
                    { Fq12::mul(12, 0) }
                } else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq12::copy(36) }
                    { Fq12::mul(12, 0) }
                }

                // update f, f = f * double_line_eval
                { Fq2::copy(50) }
                { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }

                { Fq2::copy(48) }
                { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }

                // update f (add), f = f * add_line_eval
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq2::copy(50) }
                    { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }

                    { Fq2::copy(48) }
                    { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }
                }
            }

            // update c_inv
            // f = f * c_inv^p * c^{p^2}
           { Fq12::roll(24) }
           { Fq12::frobenius_map(1) }
           { Fq12::mul(12, 0) }
           { Fq12::roll(24) }
           { Fq12::frobenius_map(2) }
           { Fq12::mul(12, 0) }

            // scale f
            // f = f * wi
            { Fq12::mul(12, 0) }
            // update f (frobenius map): f = f * add_line_eval([p])
            { Fq2::copy(14) }
            { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }

            { Fq2::copy(12) }
            { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }

            // update f (frobenius map): f = f * add_line_eval([-p^2])
            { Fq2::roll(14) }
            { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }

            { Fq2::roll(12) }
            { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }
        };

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        script
    }

    // refer algorithm 9 of https://eprint.iacr.org/2024/640.pdf
    // four pairings in total, where three of them is fixed on G2, only one is non-fixed on G2 (specially for groth16 verifier for now)
    //
    // input on stack (non-fixed): [beta^{2*(p-1)/6}, beta^{3*(p-1)/6}, beta^{2*(p^2-1)/6}, 1/2, B,   P1,   P2,   P3,   P4,   Q4,    c,    c_inv, wi,   T4]
    //                             [Fp2,              Fp2,              Fp2,                Fp,  Fp2, 2*Fp, 2*Fp, 2*Fp, 2*Fp, 2*Fp2, Fp12, Fp12,  Fp12, 3*Fp2]
    // Stack Index(Bottom,Top)     [61                59,               57,                 56,  54,  52,   50,   48,   46,   42,    30,   18,    6,    0]
    //
    // params:
    //      input outside stack (fixed): [L1, L2, L3]
    pub fn quad_miller_loop_with_c_wi(constants: &Vec<G2Prepared>) -> Script {
        let num_constant = constants.len();
        assert_eq!(num_constant, 3);
        
        let mut constant_iters = constants
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        let script = script! {

            // 1. f = c_inv
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
            { Fq12::copy(18) }
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

            // 2. miller loop part, 6x + 2
            // ATE_LOOP_COUNT len: 65
            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                // 2.1 update f (double), f = f * f
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2]
                { Fq12::square() }

                // 2.2 update c_inv
                // f = f * c_inv, if digit == 1
                // f = f * c, if digit == -1
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c_inv]
                    { Fq12::copy(30) }
                    { Fq12::mul(12, 0) }
                } else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c]
                    { Fq12::copy(42) }
                    { Fq12::mul(12, 0) }
                }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

                //////////////////////////////////////////////////////////////////// 2.3 accumulate double lines (fixed and non-fixed)
                // f = f^2 * double_line_Q(P)
                // fixed (constant part) P1, P2, P3
                // [beta_12, beta_13, beta_22, 1/2, B, P1(64), P2(62), P3(60), P4(58), Q4(54), c(42), c_inv(30), wi(18), T4(12), f]
                for j in 0..num_constant {
                    // [beta_12, beta_13, beta_22, 1/2, B, P1(64), P2(62), P3(60), P4(58), Q4(54), c(42), c_inv(30), wi(18), T4(12), f, P1]
                    { Fq2::copy((64 - j * 2) as u32) }
                    { Pairing::ell_by_constant(constant_iters[j].next().unwrap()) }
                }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

                // non-fixed (non-constant part) P4
                { Fq2::copy(/* offset_P */(46 + 12) as u32) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f, P4]
                // roll T, and double line with T (projective coordinates)
                { Fq6::roll(/* offset_T */(12 + 2) as u32) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4]
                { Pairing::double_line() }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, (,,)]
                { Fq6::roll(6) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,), T4]
                { Fq6::toaltstack() }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,) | T4]
                // line evaluation and update f
                { Fq2::roll(6) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, (,,), P4 | T4]
                { Pairing::ell() }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f | T4]
                { Fq6::fromaltstack() }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, T4]
                { Fq12::roll(6) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

                //////////////////////////////////////////////////////////////////// 2.4 accumulate add lines (fixed and non-fixed)
                // update f (add), f = f * add_line_eval
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    // f = f * add_line_Q(P)
                    // fixed (constant part), P1, P2, P3
                    for j in 0..num_constant {
                        { Fq2::copy((64 - j * 2) as u32) }
                        { Pairing::ell_by_constant(constant_iters[j].next().unwrap()) }
                    }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

                    // non-fixed (non-constant part), P4
                    { Fq2::copy(/* offset_P */(46 + 12) as u32) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f, P4]
                    // roll T and copy Q, and add line with Q and T(projective coordinates)
                    { Fq6::roll(/* offset_T */(12 + 2) as u32) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4]
                    { Fq2::copy(/* offset_Q */(48 + 2 + 6) as u32 + 2) }
                    { Fq2::copy(/* offset_Q */(48 + 2 + 6) as u32 + 2) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, Q4]
                    { Pairing::add_line_with_flag(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, (,,)]
                    { Fq6::roll(6) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,), T4]
                    { Fq6::toaltstack() }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,) | T4]
                    // line evaluation and update f
                    { Fq2::roll(6) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, (,,), P4 | T4]
                    // { Pairing::ell_by_non_constant() }
                    { Pairing::ell() }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f | T4]
                    // rollback T
                    { Fq6::fromaltstack() }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, T4]
                    { Fq12::roll(6) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
                }
            }
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
            // clean 1/2 and B in stack
            { Fq::roll(68) }
            { Fq::drop() }
            // [beta_12, beta_13, beta_22, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
            { Fq2::roll(66) }
            { Fq2::drop() }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

            /////////////////////////////////////////  update c_inv
            // 3. f = f * c_inv^p * c^{p^2}
            { Fq12::roll(30) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, wi, T4, f, c_inv]
            { Fq12::frobenius_map(1) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, wi, T4, f, c_inv^p]
            { Fq12::mul(12, 0) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, wi, T4, f]
            { Fq12::roll(30) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, wi, T4, f, c]
            { Fq12::frobenius_map(2) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, wi, T4, f,]
            { Fq12::mul(12, 0) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, wi, T4, f]
            
            //////////////////////////////////////// scale f
            // 4. f = f * wi
            { Fq12::roll(12 + 6) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f, wi]
            { Fq12::mul(12, 0) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f]

            /////////////////////////////////////// 5. one-time frobenius map on fixed and non-fixed lines
            // fixed part, P1, P2, P3
            // 5.1 update f (frobenius map): f = f * add_line_eval([p])
            for j in 0..num_constant {
                { Fq2::copy((28 - j * 2) as u32) }
                { Pairing::ell_by_constant(constant_iters[j].next().unwrap()) }
            }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f]

            // 5.2 non-fixed part, P4
            // copy P4
            { Fq2::copy(22) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f, P4]
            { Fq6::roll(14) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4]

            // 5.2.1 Qx.conjugate * beta^{2 * (p - 1) / 6}
            { Fq2::copy(/* offset_Q*/(6 + 2 + 12) as u32 + 2) }
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx]
            { Fq::neg(0) }
            // [beta_12, beta_13, beta_22, P1(32), P2, P3, P4, Q4(22), f(10), P4(8), T4, Qx']
            { Fq2::roll(/* offset_beta_12 */38_u32) }
            // [beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx', beta_12]
            { Fq2::mul(2, 0) }
            // [beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx' * beta_12]
            // [beta_13, beta_22, P1, P2, P3, P4, Q4(22), f, P4, T4, Qx]

            // 5.2.2 Qy.conjugate * beta^{3 * (p - 1) / 6}
            { Fq2::copy(/* offset_Q*/(6 + 2 + 12) as u32 + 2) }
            { Fq::neg(0) }
            // [beta_13(38), beta_22, P1, P2, P3, P4(28), Q4(24), f(12), P4(10), T4(4), Qx, Qy']
            { Fq2::roll(/* offset_beta_13 */38_u32) }
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy', beta_13]
            { Fq2::mul(2, 0) }
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy' * beta_13]
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy]

            // add line with T and phi(Q)
            { Pairing::add_line_with_flag(true) }
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, (,,)]
            { Fq6::roll(6) }
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, (,,), T4]
            { Fq6::toaltstack() }
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, (,,) | T4]

            // line evaluation and update f
            { Fq2::roll(6) }
            // [beta_22, P1, P2, P3, P4, Q4, f, (,,), P4 | T4]
            { Pairing::ell() }
            // [beta_22, P1, P2, P3, P4, Q4, f | T4]
            { Fq6::fromaltstack() }
            { Fq12::roll(6) }
            // [beta_22, P1, P2, P3, P4, Q4, T4, f]

            /////////////////////////////////////// 6. two-times frobenius map on fixed and non-fixed lines
            // 6.1 fixed part, P1, P2, P3
            for j in 0..num_constant {
                { Fq2::roll((28 - j * 2) as u32) }
                { Pairing::ell_by_constant(constant_iters[j].next().unwrap()) }
            }
            // [beta_22, P4, Q4, T4, f]

            // non-fixed part, P4
            { Fq2::roll(/* offset_P */22_u32) }
            // [beta_22, Q4, T4, f, P4]
            { Fq6::roll(14) }
            // [beta_22, Q4, f, P4, T4]

            // 6.2 phi(Q)^2
            // Qx * beta^{2 * (p^2 - 1) / 6}
            { Fq2::roll(/*offset_Q*/20 + 2) }
            // [beta_22, Qy, f, P4, T4, Qx]
            { Fq2::roll(/*offset_beta_22 */24_u32) }
            // [Qy, f, P4, T4, Qx, beta_22]
            { Fq2::mul(2, 0) }
            // [Qy, f, P4, T4, Qx * beta_22]
            // - Qy
            { Fq2::roll(22) }
            // [f, P4, T4, Qx * beta_22, Qy]
            // [f, P4, T4, Qx, Qy]

            // 6.3 add line with T and phi(Q)^2
            { Pairing::add_line_with_flag(true) }
            // [f, P4, T4, (,,)]
            { Fq6::roll(6) }
            // [f, P4, (,,), T4]
            { Fq6::drop() }
            // [f, P4, (,,)]
            // line evaluation and update f
            { Fq2::roll(6) }
            // [f, (,,), P4]
            { Pairing::ell() }
            // [f]
        };

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }
        script
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::ell_coeffs::{mul_by_char, G2Prepared};
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::pairing::Pairing;
    use crate::bn254::utils::{fq12_push, fq2_push};
    use crate::{execute_script_without_stack_limit, treepp::*};
    use ark_bn254::g2::G2Affine;
    use ark_bn254::Bn254;

    use ark_ec::pairing::Pairing as _;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::AffineRepr;

    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    use num_bigint::BigUint;
    use num_traits::Num;
    use num_traits::One;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    #[test]
    fn test_ell() {
        println!("Pairing.ell: {} bytes", Pairing::ell().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::rand(&mut prng);
            let c1 = ark_bn254::Fq2::rand(&mut prng);
            let c2 = ark_bn254::Fq2::rand(&mut prng);
            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            let b = {
                let mut c0new = c0;
                c0new.mul_assign_by_fp(&py);

                let mut c1new = c1;
                c1new.mul_assign_by_fp(&px);

                let mut b = a;
                b.mul_by_034(&c0new, &c1new, &c2);
                b
            };

            let script = script! {
                { fq12_push(a) }
                { fq2_push(c0) }
                { fq2_push(c1) }
                { fq2_push(c2) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                { Pairing::ell() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_ell_by_constant() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let coeffs = G2Prepared::from(b);

            let ell_by_constant = Pairing::ell_by_constant(&coeffs.ell_coeffs[0]);
            println!("Pairing.ell_by_constant: {} bytes", ell_by_constant.len());

            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            let b = {
                let mut c0new = coeffs.ell_coeffs[0].0;
                c0new.mul_assign_by_fp(&py);

                let mut c1new = coeffs.ell_coeffs[0].1;
                c1new.mul_assign_by_fp(&px);

                let mut b = a;
                b.mul_by_034(&c0new, &c1new, &coeffs.ell_coeffs[0].2);
                b
            };

            let script = script! {
                { fq12_push(a) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                { Pairing::ell_by_constant(&coeffs.ell_coeffs[0]) }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_miller_loop() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);
            let a_prepared = G2Prepared::from(a);

            let miller_loop = Pairing::miller_loop(&a_prepared);
            println!("Pairing.miller_loop: {} bytes", miller_loop.len());

            let c = Bn254::miller_loop(p, a).0;

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { miller_loop.clone() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_dual_miller_loop() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);
            let q = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);
            let a_prepared = G2Prepared::from(a);

            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let b_prepared = G2Prepared::from(b);

            let dual_miller_loop = Pairing::dual_miller_loop(&a_prepared, &b_prepared);
            println!("Pairing.dual_miller_loop: {} bytes", dual_miller_loop.len());

            let c = Bn254::multi_miller_loop([p, q], [a, b]).0;

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.y).to_u32_digits()) }
                { dual_miller_loop.clone() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_dual_millerloop_with_c_wi() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            // exp = 6x + 2 + p - p^2 = lambda - p^3
            let p_pow3 = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
            let lambda = BigUint::from_str(
                "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
            ).unwrap();
            let (exp, sign) = if lambda > p_pow3 {
                (lambda - p_pow3, true)
            } else {
                (p_pow3 - lambda, false)
            };
            // random c and wi
            let c = ark_bn254::Fq12::rand(&mut prng);
            let c_inv = c.inverse().unwrap();
            let wi = ark_bn254::Fq12::rand(&mut prng);

            let p = ark_bn254::G1Affine::rand(&mut prng);
            let q = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);
            let a_prepared = G2Prepared::from(a);

            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let b_prepared = G2Prepared::from(b);

            let dual_miller_loop_with_c_wi =
                Pairing::dual_miller_loop_with_c_wi(&a_prepared, &b_prepared);
            println!(
                "Pairing.dual_miller_loop_with_c_wi: {} bytes",
                dual_miller_loop_with_c_wi.len()
            );

            let f = Bn254::multi_miller_loop([p, q], [a, b]).0;
            println!("Bn254::multi_miller_loop done!");
            let hint = if sign {
                f * wi * (c_inv.pow(exp.to_u64_digits()))
            } else {
                f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
            };
            println!("Accumulated f done!");

            // p, q, c, c_inv, wi
            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.y).to_u32_digits()) }
                { fq12_push(c) }
                { fq12_push(c_inv) }
                { fq12_push(wi) }
                { dual_miller_loop_with_c_wi.clone() }
                { fq12_push(hint) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_quad_miller_loop_with_c_wi() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            // exp = 6x + 2 + p - p^2 = lambda - p^3
            let p_pow3 = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
            let lambda = BigUint::from_str(
                "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
            ).unwrap();
            let (exp, sign) = if lambda > p_pow3 {
                (lambda - p_pow3, true)
            } else {
                (p_pow3 - lambda, false)
            };
            // random c and wi
            let c = ark_bn254::Fq12::rand(&mut prng);
            let c_inv = c.inverse().unwrap();
            let wi = ark_bn254::Fq12::rand(&mut prng);

            let P1 = ark_bn254::G1Affine::rand(&mut prng);
            let P2 = ark_bn254::G1Affine::rand(&mut prng);
            let P3 = ark_bn254::G1Affine::rand(&mut prng);
            let P4 = ark_bn254::G1Affine::rand(&mut prng);

            let Q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q1_prepared = G2Prepared::from(Q1);
            let Q2_prepared = G2Prepared::from(Q2);
            let Q3_prepared = G2Prepared::from(Q3);

            let T4 = Q4.into_group();

            let quad_miller_loop_with_c_wi = Pairing::quad_miller_loop_with_c_wi(
                &[Q1_prepared, Q2_prepared, Q3_prepared].to_vec(),
            );
            println!(
                "Pairing.quad_miller_loop_with_c_wi: {} bytes",
                quad_miller_loop_with_c_wi.len()
            );

            let f = Bn254::multi_miller_loop([P1, P2, P3, P4], [Q1, Q2, Q3, Q4]).0;
            println!("Bn254::multi_miller_loop done!");
            let hint = if sign {
                f * wi * (c_inv.pow(exp.to_u64_digits()))
            } else {
                f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
            };
            println!("Accumulated f done!");

            // beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B / beta,
            // P1, P2, P3, P4, Q4, c, c_inv, wi, T4
            let script = script! {
                { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(P1.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P1.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P2.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P2.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P3.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P3.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P4.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P4.y).to_u32_digits()) }

                { fq2_push(Q4.x) }
                { fq2_push(Q4.y) }

                { fq12_push(c) }
                { fq12_push(c_inv) }
                { fq12_push(wi) }

                { fq2_push(T4.x) }
                { fq2_push(T4.y) }
                { fq2_push(T4.z) }

                { quad_miller_loop_with_c_wi.clone() }

                { fq12_push(hint) }
                { Fq12::equalverify() }

                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

                OP_TRUE
            };
            let exec_result = execute_script_without_stack_limit(script);
            println!("{}", exec_result);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul_by_char() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let q4 = G2Affine::rand(&mut rng);
        let phi_q = mul_by_char(q4);
        let mut phi_q2 = mul_by_char(phi_q);
        phi_q2.y.neg_in_place();

        let script = script! {
            // [beta_12, beta_13, beta_22]
            { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }
            // [beta_12, beta_13, beta_22, Qx, Qy]
            { Fq::push_u32_le(&BigUint::from(q4.x.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.x.c1).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.y.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.y.c1).to_u32_digits()) }
            // [beta_12, beta_13, beta_22, Qy, -Qx]
            { Fq2::roll(2) }
            { Fq::neg(0) }
            // [beta_13, beta_22, Qy, -Qx, beta_12]
            { Fq2::roll(8) }
            // [beta_13, beta_22, Qy, -Qx * beta_12]
            { Fq2::mul(2, 0) }
            // [beta_13, beta_22, -Qx * beta_12, -Qy]
            { Fq2::roll(2) }
            { Fq::neg(0) }
            // [beta_22, -Qx * beta_12, -Qy, beta_13]
            { Fq2::roll(6) }
            // [beta_22, -Qx * beta_12, -Qy * beta_13]
            { Fq2::mul(2, 0) }
            // check phi_Q
            // [beta_22, -Qx * beta_12, -Qy * beta_13, phi_q]
            { fq2_push(phi_q.y().unwrap().to_owned()) }
            { Fq2::equalverify() }
            { fq2_push(phi_q.x().unwrap().to_owned()) }
            { Fq2::equalverify() }
            // [beta_22, Qy, Qx]
            { Fq::push_u32_le(&BigUint::from(q4.y.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.y.c1).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.x.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.x.c1).to_u32_digits()) }
            // [Qy, Qx, beta_22]
            { Fq2::roll(4) }
            // [Qy, Qx * beta_22]
            { Fq2::mul(2, 0) }
            // [Qx * beta_22, Qy]
            { Fq2::roll(2) }
            // [Qx * beta_22, Qy, phi_Q2]
            { fq2_push(phi_q2.y().unwrap().to_owned()) }
            { Fq2::equalverify() }
            { fq2_push(phi_q2.x().unwrap().to_owned()) }
            { Fq2::equalverify() }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);
    }
}
