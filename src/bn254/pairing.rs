use crate::bn254::ell_coeffs::{EllCoeff, G2HomProjective, G2Prepared};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::treepp::*;
use ark_ec::bn::BnConfig;
use bitcoin::opcodes::all::{OP_FROMALTSTACK, OP_TOALTSTACK};

pub struct Pairing;

impl Pairing {
    // stack data: beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B,
    // P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Qx, Qy
    // [..., Fq12, Fq12, Fq12, Fq12, Fq, Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq)]
    pub fn add_line() -> Script {
        script! {
        // let theta = self.y - &(q.y * &self.z);
        // f, Px, Py, Tx, Ty, Tz, Qx, Qy
        { Fq2::copy(6) }
        // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty
        { Fq2::copy(2) }
        // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy
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
        { Fq2::copy(10) }
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
        { Fq2::copy(10) }
        // f, Px, Py, Qy, theta, lambda, x, y, z, theta * Qx, lambda
        { Fq2::roll(14) }
        // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda, Qy
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

    // stack data: beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B,
    // P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz
    // [..., Fq12, Fq12, Fq12, Fq12, Fq, Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq)]
    pub fn double_line() -> Script {
        script! {

        // let mut a = self.x * &self.y;
        // P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz
        { Fq2::copy(4) }
        // P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx
        { Fq2::copy(4) }
        // P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx, Ty
        { Fq2::mul(2, 0) }
        // P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx * Ty

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
        { Fq2::copy(74) }
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
        { Fq2::copy(82) }
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
        // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e + b

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
        { Fq2::roll(14) }
        // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, f, g, h, i, j, e^2, a, b
        { Fq2::roll(14) }
        // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, g, h, i, j, e^2, a, b, f
        { Fq2::sub(2, 0) }
        // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, g, h, i, j, e^2, a, b - f
        { Fq2::mul(2, 0) }
        // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, g, h, i, j, e^2, a * (b - f)

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

    // Stack top: [lamda, mu,   Q.x, Q.y ]
    // Type:      [Fq2,   Fq2, (Fq2, Fq2)]
    fn double_line_g2() -> Script {
        script! {
            // check 2*lamda*y == 3 * q.x^2
            // [lamda, mu, x, y, y ]
            { Fq2::copy(0) }
            // [lamda, mu, x, y, y, lamda ]
            { Fq2::copy(8) }
            // [lamda, mu, x, y, y * lamda ]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x, y, 2 *y * lamda ]
            { Fq2::double(0) }
            // [lamda, mu, x, y] | [ 2 *y * lamda ]
            { Fq2::toaltstack() }
            // 2 * lamda * y == 3 * x^2
            // [lamda, mu, x, y, x] | [ 2 *y * lamda ]
            { Fq2::copy(2) }
            // [lamda, mu, x, y, x^2] | [ 2 *y * lamda ]
            { Fq2::square() }
            // [lamda, mu, x, y, x^2, x^2] | [ 2 *y * lamda ]
            { Fq2::copy(0) }
            // [lamda, mu, x, y, x^2, 2x^2] | [ 2 *y * lamda ]
            { Fq2::double(0) }
            // [lamda, mu, x, y, 3x^2] | [ 2 *y * lamda ]
            { Fq2::add(0, 2) }
            // [lamda, mu, x, y, 3x^2, 2 *y * lamda ]
            { Fq2::fromaltstack() }
            // [lamda, mu, x, y]
            { Fq2::equalverify() }
            // check y - lamda * x _ mu == 0
            // [lamda, mu, x, y, mu]
            { Fq2::copy(4) }
            // [lamda, mu, x, y - mu]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x, y - mu, x]
            { Fq2::copy(2) }
            // [lamda, mu, x, y - mu, x, lamda]
            { Fq2::copy(8) }
            // [lamda, mu, x, y - mu, x * lamda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x, y - mu - x * lamda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x, y - mu - x * lamda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x]
            { Fq2::equalverify() }
            // calcylate x_3 = lamda^2 - 2x
            // [lamda, mu, x, lamda]
            { Fq2::copy(4) }
            // [lamda, mu, x, lamda^2]
            { Fq2::square() }
            // [lamda, mu, lamda^2, 2x]
            { Fq2::double(2) }
            // [lamda, mu, lamda^2 - 2x]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x3, x3 ]
            { Fq2::copy(0) }
            // [mu, x3, lamda * x3 ]
            { Fq2::mul(0, 6) }
            // [x3, lamda * x3 + mu ]
            { Fq2::add(0, 4) }
            // [x3, y3 ]
            { Fq2::neg(0) }
        }
    }

    // Stack top: [lamda, mu,  Q.x1, Q.y1, Q.x2, Q.y2 ]
    // Type:      [Fq2,   Fq2, (Fq2, Fq2), (Fq2, Fq2)]
    fn add_line_g2() -> Script {
        script! {
            // check y2 - lamda * x2 - mu == 0
            // [lamda, mu, x1, y1, x2, y2, mu]
            { Fq2::copy(8) }
            // [lamda, mu, x1, y1, x2, y2 - mu]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2]
            { Fq2::copy(2) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2, lambda]
            { Fq2::copy(12) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2 * lambda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x1, y1, x2, y2 - mu - x2 * lambda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, y1, x2, y2 - mu - x2 * lambda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x1, y1, x2]
            { Fq2::equalverify() }
            // check y1 - lamda * x1 - mu == 0
            // [lamda, mu, x1, y1, x2, mu]
            { Fq2::copy(6) }
            // [lamda, mu, x1, x2, y1 - mu]
            { Fq2::sub(4, 0) }
            // [lamda, mu, x1, x2, y1 - mu, x1]
            { Fq2::copy(4) }
            // [lamda, mu, x1, x2, y1 - mu, x1, lambda]
            { Fq2::copy(10) }
            // [lamda, mu, x1, x2, y1 - mu, x1 * lambda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x1, x2, y1 - mu - x1 * lambda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, x2, y1 - mu - x2 * lambda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x1, x2]
            { Fq2::equalverify() }
            // calcylate x_3 = lamda^2 - x1 - x2
            // [lamda, mu, x1 + x2]
            {Fq2::add(0, 2)}
            // [lamda, mu, x1 + x2, lamda]
            { Fq2::copy(4) }
            // [lamda, mu, x1 + x2, lamda^2]
            { Fq2::square() }
            // [lamda, mu, lamda^2 - (x1 + x2)]
            { Fq2::sub(0, 2) }
            // [lamda, mu, x3, x3 ]
            { Fq2::copy(0) }
            // [mu, x3, lamda * x3 ]
            { Fq2::mul(0, 6) }
            // [x3, lamda * x3 + mu ]
            { Fq2::add(0, 4) }
            // [x3, y3 ]
            { Fq2::neg(0) }
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

    // // input:
    // //  f            12 elements
    // //  p.x          1 element
    // //  p.y          1 element
    // //  c0, c1, c2
    // pub fn ell_by_non_constant() -> Script {
    //     script! {
    //         // compute the new c0
    //         { Fq::copy(6) }
    //         { Fq::roll(6) }
    //         { Fq::mul() }
    //         { Fq::roll(6) }
    //         { Fq::roll(6) }
    //         { Fq::mul() }

    //         // compute the new c1
    //         { Fq::copy(6) }
    //         { Fq::roll(6) }
    //         { Fq::mul() }
    //         { Fq::roll(6) }
    //         { Fq::roll(6) }
    //         { Fq::mul() }

    //         // compute the new f
    //         // { Fq12::mul_by_034_with_4_constant(&constant.2) }
    //         { Fq12::mul_by_034() }
    //     }
    // }

    // input:
    //  f            12 elements
    //  p.x          1 element
    //  p.y          1 element
    //
    // output:
    //  new f        12 elements
    pub fn ell_by_constant(constant: &EllCoeff) -> Script {
        script! {
            // compute the new c0
            { Fq::copy(0) }
            { Fq::mul_by_constant(&constant.0.c0) }
            { Fq::roll(1) }
            { Fq::mul_by_constant(&constant.0.c1) }

            // compute the new c1
            { Fq::copy(2) }
            { Fq::mul_by_constant(&constant.1.c0) }
            { Fq::roll(3) }
            { Fq::mul_by_constant(&constant.1.c1) }

            // compute the new f
            { Fq12::mul_by_034_with_4_constant(&constant.2) }
        }
    }

    // input:
    //   p.x
    //   p.y
    pub fn miller_loop(constant: &G2Prepared) -> Script {
        let mut script_bytes = vec![];

        script_bytes.extend(Fq12::push_one().as_bytes());

        let fq12_square = Fq12::square();

        let mut constant_iter = constant.ell_coeffs.iter();

        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                script_bytes.extend(fq12_square.as_bytes());
            }

            script_bytes.extend(Fq2::copy(12).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iter.next().unwrap()).as_bytes());

            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(12).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_iter.next().unwrap()).as_bytes());
            }
        }

        script_bytes.extend(Fq2::copy(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_iter.next().unwrap()).as_bytes());

        assert_eq!(constant_iter.next(), None);

        Script::from(script_bytes)
    }

    // input:
    //   p.x
    //   p.y
    //   q.x
    //   q.y
    pub fn dual_miller_loop(constant_1: &G2Prepared, constant_2: &G2Prepared) -> Script {
        let mut script_bytes = vec![];

        script_bytes.extend(Fq12::push_one().as_bytes());

        let fq12_square = Fq12::square();

        let mut constant_1_iter = constant_1.ell_coeffs.iter();
        let mut constant_2_iter = constant_2.ell_coeffs.iter();

        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                script_bytes.extend(fq12_square.as_bytes());
            }

            script_bytes.extend(Fq2::copy(14).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

            script_bytes.extend(Fq2::copy(12).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(14).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

                script_bytes.extend(Fq2::copy(12).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());
            }
        }

        script_bytes.extend(Fq2::copy(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::copy(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        Script::from(script_bytes)
    }

    // input on stack (non-fixed) : [P1, P2, c, c_inv, wi]
    // input outside (fixed): L1(Q1), L2(Q2)
    pub fn dual_miller_loop_with_c_wi(constant_1: &G2Prepared, constant_2: &G2Prepared) -> Script {
        let mut script_bytes: Vec<u8> = vec![];

        // f = c_inv
        script_bytes.extend(
            script! {
                { Fq12::copy(12) }
            }
            .as_bytes(),
        );

        let fq12_square = Fq12::square();

        let mut constant_1_iter = constant_1.ell_coeffs.iter();
        let mut constant_2_iter = constant_2.ell_coeffs.iter();
        // miller loop part, 6x + 2
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];

            // update f (double), f = f * f
            script_bytes.extend(fq12_square.as_bytes());

            // update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            if bit == 1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(24) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            } else if bit == -1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(36) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            }

            // update f, f = f * double_line_eval
            script_bytes.extend(Fq2::copy(50).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

            script_bytes.extend(Fq2::copy(48).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

            // update f (add), f = f * add_line_eval
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(50).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

                script_bytes.extend(Fq2::copy(48).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());
            }

            println!("Miller loop [{}]", i - 1);
        }

        // update c_inv
        // f = f * c_inv^p * c^{p^2}
        script_bytes.extend(
            script! {
                { Fq12::roll(24) }
                { Fq12::frobenius_map(1) }
                { Fq12::mul(12, 0) }
                { Fq12::roll(24) }
                { Fq12::frobenius_map(2) }
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );

        // scale f
        // f = f * wi
        script_bytes.extend(
            script! {
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );

        // update f (frobenius map): f = f * add_line_eval([p])
        script_bytes.extend(Fq2::copy(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::copy(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

        // update f (frobenius map): f = f * add_line_eval([-p^2])
        script_bytes.extend(Fq2::roll(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        Script::from(script_bytes)
    }

    // input on stack (non-fixed) : [beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
    // [Fp2, Fp2, Fp2, Fp, Fp2, 2 * Fp, 2 * Fp, 2 * Fp, 2 * Fp, 2 * Fp2, Fp12, Fp12, Fp12, 3 * Fp2]
    // [59, 57, 56, 54, 52, 50, 48, 46, 42, 30, 18, 6, 0]
    // ind_beta_12 = 61,
    // ind_beta_13 = 59,
    // ind_beta_22 = 57,
    // ind_2_div_1 = 56,
    // ind_B = 54,
    // ind_P1 = 52,
    // ind_P2 = 50,
    // ind_P3 = 48,
    // ind_P4 = 46,
    // ind_Q4 = 42,
    // ind_c = 30,
    // ind_c_inv = 18,
    // ind_wi = 6
    // ind_T4 = 0
    // input outside stack (fixed): [L1, L2, L3]
    pub fn quad_miller_loop_with_c_wi(constants: &Vec<G2Prepared>) -> Script {
        let num_constant = constants.len();
        assert_eq!(num_constant, 3);
        let num_non_constant = 1;
        let num_pairs = 4;
        let mut script_bytes: Vec<u8> = vec![];

        // f = c_inv
        script_bytes.extend(
            script! {
                { Fq12::copy(18) }
            }
            .as_bytes(),
        );
        // ..., T, f

        let fq12_square = Fq12::square();

        let mut constant_iters = constants
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        // miller loop part, 6x + 2
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];

            // update f (double), f = f * f
            script_bytes.extend(fq12_square.as_bytes());

            // update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            if bit == 1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(30) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            } else if bit == -1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(42) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            }

            ////////////////////////// accumulate double lines (fixed and non-fixed)
            // f = f^2 * double_line_Q(P)
            // fixed (constant part)
            for j in 0..num_constant {
                // let offset = (4 * 12) as u32
                //     + (num_non_constant * 3 * 2) as u32
                //     + (num_non_constant * 2 * 2) as u32
                //     + (num_pairs - 1 - j) as u32 * 2;
                let offset = (52 + 12 - j * 2) as u32;
                script_bytes.extend(Fq2::copy(offset).as_bytes());
                script_bytes.extend(
                    Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes(),
                );
            }
            // ..., f

            // non-fixed (non-constant part)
            //let offset_P = (4 * 12) as u32
            //    + (num_non_constant * 3 * 2) as u32
            //    + (num_non_constant * 2 * 2) as u32;
            let offset_P = (46 + 12) as u32;
            script_bytes.extend(Fq2::copy(offset_P).as_bytes());
            // ..., f, P
            // roll T, and double line with T (projective coordinates)
            let offset_T = (12 + 2) as u32;
            script_bytes.extend(Fq6::roll(offset_T).as_bytes());
            // ..., f, P, T
            script_bytes.extend(Pairing::double_line().as_bytes());
            script_bytes.extend(Fq6::toaltstack().as_bytes());
            // ..., f, P, (, ,) | T
            // line evaluation and update f
            // script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
            script_bytes.extend(Fq2::roll(6).as_bytes());
            script_bytes.extend(Pairing::ell().as_bytes());
            // ..., f | T
            // rollback T
            script_bytes.extend(Fq6::fromaltstack().as_bytes());
            script_bytes.extend(Fq12::roll(6).as_bytes());
            // ..., T, f

            // update f (add), f = f * add_line_eval
            if bit == 1 || bit == -1 {
                // f = f * add_line_Q(P)
                // fixed (constant part)
                for j in 0..num_constant {
                    // let offset = (4 * 12) as u32
                    //     + (num_non_constant * 3 * 2) as u32
                    //     + (num_non_constant * 2 * 2) as u32
                    //     + (num_pairs - 1 - j) as u32 * 2;
                    let offset = (52 + 12 - j * 2) as u32;
                    script_bytes.extend(Fq2::copy(offset).as_bytes());
                    script_bytes.extend(
                        Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes(),
                    );
                }
                // ..., T, f

                // non-fixed (non-constant part)
                // let offset_P = (4 * 12) as u32
                //     + (num_non_constant * 3 * 2) as u32
                //     + (num_non_constant * 2 * 2) as u32;
                let offset_P = (46 + 12) as u32;
                script_bytes.extend(Fq2::copy(offset_P).as_bytes());
                // ..., T, f, P
                // roll T and copy Q, and add line with T and Q(projective coordinates)
                let offset_T = (12 + 2) as u32;
                script_bytes.extend(Fq6::roll(offset_T).as_bytes());
                // ..., f, P, T
                // let offset_Q = (4 * 12 + num_non_constant * 3 * 2) as u32;
                let offset_Q = (42 + 12 + 2 + 6) as u32;
                script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
                script_bytes.extend(Fq2::copy(offset_Q).as_bytes());
                // ..., f, P, T, Q
                script_bytes.extend(Pairing::add_line().as_bytes());
                script_bytes.extend(Fq6::toaltstack().as_bytes());
                // ..., f, P, (, ,) | T
                // line evaluation and update f
                script_bytes.extend(Fq2::roll(6).as_bytes());
                // script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
                script_bytes.extend(Pairing::ell().as_bytes());
                // ..., f | T
                // rollback T
                script_bytes.extend(Fq6::fromaltstack().as_bytes());
                script_bytes.extend(Fq12::roll(6).as_bytes());
                // ..., T, f
            }

            println!("Miller loop [{}]", i - 1);
        }
        // ..., T, f

        // update c_inv
        // f = f * c_inv^p * c^{p^2}
        script_bytes.extend(
            script! {
                { Fq12::roll(30 + 12) }
                { Fq12::frobenius_map(1) }
                { Fq12::mul(12, 0) }
                // ..., P4, Q4, c', wi, T, f
                { Fq12::roll(30 + 12 - 12) }
                { Fq12::frobenius_map(2) }
                { Fq12::mul(12, 0) }
                // ..., P4, Q4, wi, T, f
            }
            .as_bytes(),
        );
        // ..., P4, Q4, wi, T, f

        // scale f
        // f = f * wi
        script_bytes.extend(
            script! {
                { Fq12::roll(12 + 6) }
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );
        // ..., P4, Q4, T, f

        // frobenius map on fixed and non-fixed lines
        // update f (frobenius map): f = f * add_line_eval([p])
        for j in 0..num_constant {
            // let offset = (12
            //     + num_non_constant * 3 * 2
            //     + num_non_constant * 2 * 2
            //     + (num_pairs - 1 - i) * 2) as u32;
            let offset = (52 + 12 - 3 * 12 - j * 2) as u32;
            script_bytes.extend(Fq2::copy(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes());
        }
        // ..., P4, Q4, T, f

        // non-fixed
        // copy P, and T
        script_bytes.extend(Fq2::copy(46 - 12 * 3 + 12).as_bytes());
        // ..., P4, Q4, T, f, P4
        script_bytes.extend(Fq6::roll(12 + 2).as_bytes());
        // ..., P4, Q4, f, P4, T

        // // copy Q
        // let offset_Q = (6 + 2 + 12 + 6) as u32;
        // script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
        // script_bytes.extend(Fq2::copy(offset_Q).as_bytes());

        // phi(Q)
        // Qx.conjugate * beta^{2 * (p - 1) / 6}
        let offset_Q = (6 + 2 + 12) as u32;
        script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
        script_bytes.extend(Fq::neg(0).as_bytes());
        // ..., P4, Q4, f, P4, T, Qx
        let offset_beta_12 = (61 - 3 * 12 + 12 + 2 + 6 + 2) as u32;
        script_bytes.extend(Fq2::copy(offset_beta_12).as_bytes());
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // ..., P4, Q4, f, P4, T, Qx
        // Qy.conjugate * beta^{3 * (p - 1) / 6}
        script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
        script_bytes.extend(Fq::neg(0).as_bytes());
        // ..., P4, Q4, f, P4, T, Qx, Qy
        let offset_beta_13 = (59 - 3 * 12 + 12 + 2 + 6 + 4) as u32;
        script_bytes.extend(Fq2::copy(offset_beta_13).as_bytes());
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // ..., P4, Q4, f, P4, T, Qx, Qy

        // add line with T and phi(Q)
        script_bytes.extend(Pairing::add_line().as_bytes());
        script_bytes.extend(Fq6::toaltstack().as_bytes());
        // ..., P4, Q4, f, P4, (,,) | T

        // line evaluation and update f
        script_bytes.extend(Fq2::roll(6).as_bytes());
        // script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
        script_bytes.extend(Pairing::ell().as_bytes());
        // ..., P4, Q4, f | T
        script_bytes.extend(Fq6::fromaltstack().as_bytes());
        script_bytes.extend(Fq12::roll(6).as_bytes());
        // ..., P4, Q4, T, f

        for j in 0..num_constant {
            // let offset = (12
            //     + num_non_constant * 3 * 2
            //     + num_non_constant * 2 * 2
            //     + (num_pairs - 1 - i) * 2) as u32;
            let offset = (52 + 12 - 3 * 12 - j * 2) as u32;
            script_bytes.extend(Fq2::roll(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes());
        }
        // ..., P4, Q4, T, f

        // non-fixed
        // copy P, and T
        let offset_P = (46 - 3 * 12 + 12) as u32;
        script_bytes.extend(Fq2::roll(offset_P).as_bytes());
        // ..., Q4, T, f, P4
        script_bytes.extend(Fq6::roll(12 + 2).as_bytes());
        // ..., Q4, f, P4, T

        // phi(Q)
        // Qx * beta^{2 * (p^2 - 1) / 6}
        let offset_Q = 6 + 2 + 12;
        script_bytes.extend(Fq2::roll(offset_Q + 2).as_bytes());
        // beta_12, beta_13, beta_22, 1/2, B, Qy, f, P4, T, Qx
        let offset_beta_22 = (2 + 6 + 2 + 12 + 2 + 2 + 1) as u32;
        script_bytes.extend(Fq2::roll(offset_beta_22).as_bytes());
        // beta_12, beta_13, 1/2, B, Qy, f, P4, T, Qx, beta_22
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // beta_12, beta_13, 1/2, B, Qy, f, P4, T, Qx
        // - Qy
        script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
        script_bytes.extend(Fq2::neg(0).as_bytes());
        // beta_12, beta_13, 1/2, B, f, P4, T, Qx, Qy

        // add line with T and phi(Q)
        script_bytes.extend(Pairing::add_line().as_bytes());
        // beta_12, beta_13, 1/2, B, f, P4, (,,), T
        script_bytes.extend(Fq6::drop().as_bytes());
        // beta_12, beta_13, 1/2, B, f, P4, (,,)
        // line evaluation and update f
        // script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
        script_bytes.extend(Fq2::roll(6).as_bytes());
        script_bytes.extend(Pairing::ell().as_bytes());
        // beta_12, beta_13, 1/2, B, f

        // TODO, need to be removed
        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Fq2::drop().as_bytes());
        script_bytes.extend(Fq::roll(12).as_bytes());
        script_bytes.extend(Fq::drop().as_bytes());
        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Fq2::drop().as_bytes());
        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Fq2::drop().as_bytes());

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }

        Script::from(script_bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::ell_coeffs::{G2HomProjective, G2Prepared};
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::fq6::Fq6;
    use crate::bn254::pairing::Pairing;
    use crate::treepp::*;
    use ark_bn254::{Bn254, G2Affine};
    use ark_ec::bn::{BnConfig, TwistType};
    use ark_ec::pairing::Pairing as _;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    use num_bigint::BigUint;
    use num_traits::Num;
    use num_traits::One;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    use ark_bn254::G1Affine;
    use ark_ec::Group;
    use ark_ff::PrimeField;
    use num_traits::Zero;
    use std::ops::{Add, Div, Mul, Neg, Sub};

    fn fq2_push(element: ark_bn254::Fq2) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
        }
    }

    fn fq12_push(element: ark_bn254::Fq12) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

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
                let mut c0new = c0.clone();
                c0new.mul_assign_by_fp(&py);

                let mut c1new = c1.clone();
                c1new.mul_assign_by_fp(&px);

                let mut b = a.clone();
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
                let mut c0new = coeffs.ell_coeffs[0].0.clone();
                c0new.mul_assign_by_fp(&py);

                let mut c1new = coeffs.ell_coeffs[0].1.clone();
                c1new.mul_assign_by_fp(&px);

                let mut b = a.clone();
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

            let dual_miller_loop_with_c_wi = Pairing::quad_miller_loop_with_c_wi(
                &[Q1_prepared, Q2_prepared, Q3_prepared].to_vec(),
            );
            println!(
                "Pairing.dual_miller_loop_with_c_wi: {} bytes",
                dual_miller_loop_with_c_wi.len()
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
                { Fq::push_u32_le(&BigUint::from(Q4.x.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(Q4.x.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(Q4.y.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(Q4.y.c1).to_u32_digits()) }

                { fq12_push(c) }
                { fq12_push(c_inv) }
                { fq12_push(wi) }

                { Fq::push_u32_le(&BigUint::from(T4.x.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(T4.x.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(T4.y.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(T4.y.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(T4.z.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(T4.z.c1).to_u32_digits()) }

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
    fn test_double_line() {
        let mut rng = test_rng();

        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();

        let beta_x: String = ark_bn254::g2::Config::COEFF_B.c0.to_string();
        let beta_y: String = ark_bn254::g2::Config::COEFF_B.c1.to_string();

        let q_x = ark_bn254::Fq2::rand(&mut rng);
        let q_y = ark_bn254::Fq2::rand(&mut rng);
        let q_z = ark_bn254::Fq2::rand(&mut rng);

        let mut expect = G2HomProjective {
            x: q_x,
            y: q_y,
            z: q_z,
        };
        expect.double_in_place(&two_inv);

        let script = script! {
            // push 1/2
            { Fq::push_u32_le(BigUint::from_str(two_inv.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            // push BETA
            { Fq::push_u32_le(BigUint::from_str(beta_x.as_str()).unwrap().to_u32_digits().as_slice()) }
            { Fq::push_u32_le(BigUint::from_str(beta_y.as_str()).unwrap().to_u32_digits().as_slice()) }
            // push Q.x
            { Fq::push_u32_le(BigUint::from_str(q_x.c0.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            { Fq::push_u32_le(BigUint::from_str(q_x.c1.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            // push Q.y
            { Fq::push_u32_le(BigUint::from_str(q_y.c0.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            { Fq::push_u32_le(BigUint::from_str(q_y.c1.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            // push Q.z
            { Fq::push_u32_le(BigUint::from_str(q_z.c0.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            { Fq::push_u32_le(BigUint::from_str(q_z.c1.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            // double line
            { Pairing::double_line() }
            // push expect.x
            { Fq::push_u32_le(BigUint::from_str(expect.x.c0.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            { Fq::push_u32_le(BigUint::from_str(expect.x.c1.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            // push expect.y
            { Fq::push_u32_le(BigUint::from_str(expect.y.c0.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            { Fq::push_u32_le(BigUint::from_str(expect.y.c1.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            // push expect.z
            { Fq::push_u32_le(BigUint::from_str(expect.z.c0.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            { Fq::push_u32_le(BigUint::from_str(expect.z.c1.to_string().as_str()).unwrap().to_u32_digits().as_slice()) }
            { Fq6::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_double_line_g2() {
        println!(
            "double_line_g2_script.len() = {}",
            Pairing::double_line_g2().len()
        );

        let mut rng = test_rng();
        let q = G2Affine::rand(&mut rng);
        let (lamda, mu, x3, y3) = line_double(&q);

        let script = script! {
            { fq2_push(lamda) }
            { fq2_push(mu) }
            { fq2_push(q.x().unwrap().to_owned()) }
            { fq2_push(q.y().unwrap().to_owned()) }
            { Pairing::double_line_g2() }
            { fq2_push(y3) }
            { Fq2::equalverify() }
            { fq2_push(x3) }
            { Fq2::equalverify() }
            OP_TRUE
        };

        let exec_result = execute_script(script.clone());
        assert!(exec_result.success);
    }

    #[test]
    fn test_add_line_g2() {
        println!("add_line_g2_cript.len() = {}", Pairing::add_line_g2().len());

        let mut rng = test_rng();
        let q1 = G2Affine::rand(&mut rng);
        let q2 = G2Affine::rand(&mut rng);
        let (lamda, mu, x3, y3) = line_add(&q1, &q2);

        let script = script! {
            { fq2_push(lamda) }
            { fq2_push(mu) }
            { fq2_push(q1.x().unwrap().to_owned()) }
            { fq2_push(q1.y().unwrap().to_owned()) }
            { fq2_push(q2.x().unwrap().to_owned()) }
            { fq2_push(q2.y().unwrap().to_owned()) }
            { Pairing::add_line_g2() }
            { fq2_push(y3) }
            { Fq2::equalverify() }
            { fq2_push(x3) }
            { Fq2::equalverify() }
            OP_TRUE
        };

        let exec_result = execute_script(script.clone());
        assert!(exec_result.success);
    }

    fn line_double(
        point: &G2Affine,
    ) -> (
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
    ) {
        let (x, y) = (point.x, point.y);

        // slope: alpha = 3 * x ^ 2 / (2 * y)
        let alpha = x
            .square()
            .mul(ark_bn254::Fq2::from(3))
            .div(y.mul(ark_bn254::Fq2::from(2)));
        // bias = y - alpha * x
        let bias = y - alpha * x;

        let x3 = alpha.square() - x.double();
        let y3 = -(bias + alpha * x3);

        (alpha, bias, x3, y3)
    }

    fn line_add(
        point1: &G2Affine,
        point2: &G2Affine,
    ) -> (
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
    ) {
        let (x1, y1) = (point1.x, point1.y);
        let (x2, y2) = (point2.x, point2.y);

        // slope: alpha = (y2-y1)/(x2-x1)
        let alpha = (y2.sub(y1)).div(x2.sub(x1));
        // bias = y1 - alpha * x1
        let bias = y1 - alpha * x1;

        let x3 = alpha.square() - x1 - x2;
        let y3 = -(bias + alpha * x3);

        (alpha, bias, x3, y3)
    }
}
