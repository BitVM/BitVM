#![allow(non_snake_case)]
use crate::bn254::ell_coeffs::{EllCoeff, G2Prepared};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::utils;
use crate::treepp::*;
use ark_ec::bn::BnConfig;
use ark_ff::fp2::Fp2 as ark_fq2;
use ark_ff::Field;

pub struct Pairing;

impl Pairing {
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

    // stack input:
    //  f            12 elements
    //  x': -p.x / p.y   1 element
    //  y': 1 / p.y      1 element
    // func params:
    //  (c0, c1, c2) where c0 is a trival value ONE in affine mode
    //
    // output:
    //  new f        12 elements
    pub fn ell_by_constant_affine(constant: &EllCoeff) -> Script {
        assert_eq!(constant.0, ark_fq2::ONE);
        script! {
            // [f, x', y']
            // update c1, c1' = x' * c1
            { Fq::copy(1) }
            { Fq::mul_by_constant(&constant.1.c0) }
            // [f, x', y', x' * c1.0]
            { Fq::roll(2) }
            { Fq::mul_by_constant(&constant.1.c1) }
            // [f, y', x' * c1.0, x' * c1.1]
            // [f, y', x' * c1]

            // update c2, c2' = -y' * c2
            { Fq::copy(2) }
            { Fq::mul_by_constant(&constant.2.c0) }
            // [f, y', x' * c1, y' * c2.0]
            { Fq::roll(3) }
            { Fq::mul_by_constant(&constant.2.c1) }
            // [f, x' * c1, y' * c2.0, y' * c2.1]
            // [f, x' * c1, y' * c2]
            // [f, c1', c2']

            // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
            { Fq12::mul_by_34() }
            // [f]
        }
    }

    // input:
    //   p.x
    //   p.y
    pub fn miller_loop(constant: &G2Prepared, affine: bool) -> Script {
        let mut script_bytes = vec![];

        script_bytes.extend(Fq12::push_one().as_bytes());

        let fq12_square = Fq12::square();

        let mut constant_iter = constant.ell_coeffs.iter();

        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                script_bytes.extend(fq12_square.as_bytes());
            }

            script_bytes.extend(Fq2::copy(12).as_bytes());
            if affine {
                script_bytes.extend(
                    Pairing::ell_by_constant_affine(constant_iter.next().unwrap()).as_bytes(),
                );
            } else {
                script_bytes
                    .extend(Pairing::ell_by_constant(constant_iter.next().unwrap()).as_bytes());
            }

            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(12).as_bytes());
                if affine {
                    script_bytes.extend(
                        Pairing::ell_by_constant_affine(constant_iter.next().unwrap()).as_bytes(),
                    );
                } else {
                    script_bytes
                        .extend(Pairing::ell_by_constant(constant_iter.next().unwrap()).as_bytes());
                }
            }
        }

        script_bytes.extend(Fq2::copy(12).as_bytes());
        if affine {
            script_bytes
                .extend(Pairing::ell_by_constant_affine(constant_iter.next().unwrap()).as_bytes());
        } else {
            script_bytes.extend(Pairing::ell_by_constant(constant_iter.next().unwrap()).as_bytes());
        }

        script_bytes.extend(Fq2::roll(12).as_bytes());
        if affine {
            script_bytes
                .extend(Pairing::ell_by_constant_affine(constant_iter.next().unwrap()).as_bytes());
        } else {
            script_bytes.extend(Pairing::ell_by_constant(constant_iter.next().unwrap()).as_bytes());
        }

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
                .extend(Pairing::ell_by_constant(constant_1_iter.next().unwrap()).as_bytes());

            script_bytes.extend(Fq2::copy(12).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(constant_2_iter.next().unwrap()).as_bytes());

            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(14).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(constant_1_iter.next().unwrap()).as_bytes());

                script_bytes.extend(Fq2::copy(12).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(constant_2_iter.next().unwrap()).as_bytes());
            }
        }

        script_bytes.extend(Fq2::copy(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::copy(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(constant_2_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(constant_2_iter.next().unwrap()).as_bytes());

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        Script::from(script_bytes)
    }

    // input on stack (non-fixed) : [P1, P2, c, c_inv, wi]
    // input outside (fixed): L1(Q1), L2(Q2)
    pub fn dual_miller_loop_with_c_wi(
        constant_1: &G2Prepared,
        constant_2: &G2Prepared,
        affine: bool,
    ) -> Script {
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
            // f = f * c_inv, if bit == 1
            // f = f * c, if bit == -1
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
            if affine {
                script_bytes.extend(
                    Pairing::ell_by_constant_affine(constant_1_iter.next().unwrap()).as_bytes(),
                );
            } else {
                script_bytes
                    .extend(Pairing::ell_by_constant(constant_1_iter.next().unwrap()).as_bytes());
            }

            script_bytes.extend(Fq2::copy(48).as_bytes());
            if affine {
                script_bytes.extend(
                    Pairing::ell_by_constant_affine(constant_2_iter.next().unwrap()).as_bytes(),
                );
            } else {
                script_bytes
                    .extend(Pairing::ell_by_constant(constant_2_iter.next().unwrap()).as_bytes());
            }

            // update f (add), f = f * add_line_eval
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(50).as_bytes());
                if affine {
                    script_bytes.extend(
                        Pairing::ell_by_constant_affine(constant_1_iter.next().unwrap()).as_bytes(),
                    );
                } else {
                    script_bytes.extend(
                        Pairing::ell_by_constant(constant_1_iter.next().unwrap()).as_bytes(),
                    );
                }

                script_bytes.extend(Fq2::copy(48).as_bytes());
                if affine {
                    script_bytes.extend(
                        Pairing::ell_by_constant_affine(constant_2_iter.next().unwrap()).as_bytes(),
                    );
                } else {
                    script_bytes.extend(
                        Pairing::ell_by_constant(constant_2_iter.next().unwrap()).as_bytes(),
                    );
                }
            }
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
        if affine {
            script_bytes.extend(
                Pairing::ell_by_constant_affine(constant_1_iter.next().unwrap()).as_bytes(),
            );
        } else {
            script_bytes
                .extend(Pairing::ell_by_constant(constant_1_iter.next().unwrap()).as_bytes());
        }

        script_bytes.extend(Fq2::copy(12).as_bytes());
        if affine {
            script_bytes.extend(
                Pairing::ell_by_constant_affine(constant_2_iter.next().unwrap()).as_bytes(),
            );
        } else {
            script_bytes
                .extend(Pairing::ell_by_constant(constant_2_iter.next().unwrap()).as_bytes());
        }

        // update f (frobenius map): f = f * add_line_eval([-p^2])
        script_bytes.extend(Fq2::roll(14).as_bytes());
        if affine {
            script_bytes.extend(
                Pairing::ell_by_constant_affine(constant_1_iter.next().unwrap()).as_bytes(),
            );
        } else {
            script_bytes
                .extend(Pairing::ell_by_constant(constant_1_iter.next().unwrap()).as_bytes());
        }

        script_bytes.extend(Fq2::roll(12).as_bytes());
        if affine {
            script_bytes.extend(
                Pairing::ell_by_constant_affine(constant_2_iter.next().unwrap()).as_bytes(),
            );
        } else {
            script_bytes
                .extend(Pairing::ell_by_constant(constant_2_iter.next().unwrap()).as_bytes());
        }

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        Script::from(script_bytes)
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
        let mut script_bytes: Vec<u8> = vec![];

        // 1. f = c_inv
        // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
        script_bytes.extend(
            script! {
                { Fq12::copy(18) }
            }
            .as_bytes(),
        );
        // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

        let fq12_square = Fq12::square();

        let mut constant_iters = constants
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        // 2. miller loop part, 6x + 2
        // ATE_LOOP_COUNT len: 65
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];

            // 2.1 update f (double), f = f * f
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2]
            script_bytes.extend(fq12_square.as_bytes());

            // 2.2 update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            if bit == 1 {
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c_inv]
                script_bytes.extend(
                    script! {
                        { Fq12::copy(30) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            } else if bit == -1 {
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c]
                script_bytes.extend(
                    script! {
                        { Fq12::copy(42) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            }
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

            //////////////////////////////////////////////////////////////////// 2.3 accumulate double lines (fixed and non-fixed)
            // f = f^2 * double_line_Q(P)
            // fixed (constant part) P1, P2, P3
            // [beta_12, beta_13, beta_22, 1/2, B, P1(64), P2(62), P3(60), P4(58), Q4(54), c(42), c_inv(30), wi(18), T4(12), f]
            for j in 0..num_constant {
                let offset = (64 - j * 2) as u32;
                // [beta_12, beta_13, beta_22, 1/2, B, P1(64), P2(62), P3(60), P4(58), Q4(54), c(42), c_inv(30), wi(18), T4(12), f, P1]
                script_bytes.extend(Fq2::copy(offset).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(constant_iters[j].next().unwrap()).as_bytes());
            }
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

            // non-fixed (non-constant part) P4
            let offset_P = (46 + 12) as u32;
            script_bytes.extend(Fq2::copy(offset_P).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f, P4]
            // roll T, and double line with T (projective coordinates)
            let offset_T = (12 + 2) as u32;
            script_bytes.extend(Fq6::roll(offset_T).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4]
            script_bytes.extend(utils::double_line().as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, (,,)]
            script_bytes.extend(Fq6::roll(6).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,), T4]
            script_bytes.extend(Fq6::toaltstack().as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,) | T4]
            // line evaluation and update f
            script_bytes.extend(Fq2::roll(6).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, (,,), P4 | T4]
            script_bytes.extend(Pairing::ell().as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f | T4]
            script_bytes.extend(Fq6::fromaltstack().as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, T4]
            script_bytes.extend(Fq12::roll(6).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

            //////////////////////////////////////////////////////////////////// 2.4 accumulate add lines (fixed and non-fixed)
            // update f (add), f = f * add_line_eval
            if bit == 1 || bit == -1 {
                // f = f * add_line_Q(P)
                // fixed (constant part), P1, P2, P3
                for j in 0..num_constant {
                    let offset = (64 - j * 2) as u32;
                    script_bytes.extend(Fq2::copy(offset).as_bytes());
                    script_bytes.extend(
                        Pairing::ell_by_constant(constant_iters[j].next().unwrap()).as_bytes(),
                    );
                }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

                // non-fixed (non-constant part), P4
                let offset_P = (46 + 12) as u32;
                script_bytes.extend(Fq2::copy(offset_P).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f, P4]
                // roll T and copy Q, and add line with Q and T(projective coordinates)
                let offset_T = (12 + 2) as u32;
                script_bytes.extend(Fq6::roll(offset_T).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4]
                let offset_Q = (48 + 2 + 6) as u32;
                script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
                script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, Q4]
                script_bytes.extend(utils::add_line_with_flag(bit == 1).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, (,,)]
                script_bytes.extend(Fq6::roll(6).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,), T4]
                script_bytes.extend(Fq6::toaltstack().as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,) | T4]
                // line evaluation and update f
                script_bytes.extend(Fq2::roll(6).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, (,,), P4 | T4]
                // script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
                script_bytes.extend(Pairing::ell().as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f | T4]
                // rollback T
                script_bytes.extend(Fq6::fromaltstack().as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, T4]
                script_bytes.extend(Fq12::roll(6).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
            }
        }

        // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
        // clean 1/2 and B in stack
        script_bytes.extend(Fq::roll(68).as_bytes());
        script_bytes.extend(Fq::drop().as_bytes());
        // [beta_12, beta_13, beta_22, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
        script_bytes.extend(Fq2::roll(66).as_bytes());
        script_bytes.extend(Fq2::drop().as_bytes());
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

        /////////////////////////////////////////  update c_inv
        // 3. f = f * c_inv^p * c^{p^2}
        script_bytes.extend(
            script! {
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
            }
            .as_bytes(),
        );
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, wi, T4, f]
        //////////////////////////////////////// scale f
        // 4. f = f * wi
        script_bytes.extend(
            script! {
                { Fq12::roll(12 + 6) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f, wi]
                { Fq12::mul(12, 0) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f]
            }
            .as_bytes(),
        );
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f]

        /////////////////////////////////////// 5. one-time frobenius map on fixed and non-fixed lines
        // fixed part, P1, P2, P3
        // 5.1 update f (frobenius map): f = f * add_line_eval([p])
        for j in 0..num_constant {
            let offset = (28 - j * 2) as u32;
            script_bytes.extend(Fq2::copy(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(constant_iters[j].next().unwrap()).as_bytes());
        }
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f]

        // 5.2 non-fixed part, P4
        // copy P4
        script_bytes.extend(Fq2::copy(22).as_bytes());
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f, P4]
        script_bytes.extend(Fq6::roll(14).as_bytes());
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4]

        // 5.2.1 Qx.conjugate * beta^{2 * (p - 1) / 6}
        let offset_Q = (6 + 2 + 12) as u32;
        script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx]
        script_bytes.extend(Fq::neg(0).as_bytes());
        // [beta_12, beta_13, beta_22, P1(32), P2, P3, P4, Q4(22), f(10), P4(8), T4, Qx']
        let offset_beta_12 = 38_u32;
        script_bytes.extend(Fq2::roll(offset_beta_12).as_bytes());
        // [beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx', beta_12]
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // [beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx' * beta_12]
        // [beta_13, beta_22, P1, P2, P3, P4, Q4(22), f, P4, T4, Qx]

        // 5.2.2 Qy.conjugate * beta^{3 * (p - 1) / 6}
        script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
        script_bytes.extend(Fq::neg(0).as_bytes());
        // [beta_13(38), beta_22, P1, P2, P3, P4(28), Q4(24), f(12), P4(10), T4(4), Qx, Qy']
        let offset_beta_13 = 38_u32;
        script_bytes.extend(Fq2::roll(offset_beta_13).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy', beta_13]
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy' * beta_13]
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy]

        // add line with T and phi(Q)
        script_bytes.extend(utils::add_line_with_flag(true).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, (,,)]
        script_bytes.extend(Fq6::roll(6).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, (,,), T4]
        script_bytes.extend(Fq6::toaltstack().as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, (,,) | T4]

        // line evaluation and update f
        script_bytes.extend(Fq2::roll(6).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, (,,), P4 | T4]
        script_bytes.extend(Pairing::ell().as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f | T4]
        script_bytes.extend(Fq6::fromaltstack().as_bytes());
        script_bytes.extend(Fq12::roll(6).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, T4, f]

        /////////////////////////////////////// 6. two-times frobenius map on fixed and non-fixed lines
        // 6.1 fixed part, P1, P2, P3
        for j in 0..num_constant {
            let offset = (28 - j * 2) as u32;
            script_bytes.extend(Fq2::roll(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(constant_iters[j].next().unwrap()).as_bytes());
        }
        // [beta_22, P4, Q4, T4, f]

        // non-fixed part, P4
        let offset_P = 22_u32;
        script_bytes.extend(Fq2::roll(offset_P).as_bytes());
        // [beta_22, Q4, T4, f, P4]
        script_bytes.extend(Fq6::roll(14).as_bytes());
        // [beta_22, Q4, f, P4, T4]

        // 6.2 phi(Q)^2
        // Qx * beta^{2 * (p^2 - 1) / 6}
        let offset_Q = 20;
        script_bytes.extend(Fq2::roll(offset_Q + 2).as_bytes());
        // [beta_22, Qy, f, P4, T4, Qx]
        let offset_beta_22 = 24_u32;
        script_bytes.extend(Fq2::roll(offset_beta_22).as_bytes());
        // [Qy, f, P4, T4, Qx, beta_22]
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // [Qy, f, P4, T4, Qx * beta_22]
        // - Qy
        script_bytes.extend(Fq2::roll(22).as_bytes());
        // [f, P4, T4, Qx * beta_22, Qy]
        // [f, P4, T4, Qx, Qy]

        // 6.3 add line with T and phi(Q)^2
        script_bytes.extend(utils::add_line_with_flag(true).as_bytes());
        // [f, P4, T4, (,,)]
        script_bytes.extend(Fq6::roll(6).as_bytes());
        // [f, P4, (,,), T4]
        script_bytes.extend(Fq6::drop().as_bytes());
        // [f, P4, (,,)]
        // line evaluation and update f
        script_bytes.extend(Fq2::roll(6).as_bytes());
        // [f, (,,), P4]
        script_bytes.extend(Pairing::ell().as_bytes());
        // [f]

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }

        Script::from(script_bytes)
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

    use crate::bn254::utils;
    use ark_ff::AdditiveGroup;
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
    fn test_ell_by_constant_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            // projective mode
            let coeffs = G2Prepared::from(b);
            let ell_by_constant = Pairing::ell_by_constant(&coeffs.ell_coeffs[0]);
            println!("Pairing.ell_by_constant: {} bytes", ell_by_constant.len());

            // projective mode as well
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
    fn test_ell_by_constant_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b);
        let ell_by_constant_affine_script = Pairing::ell_by_constant_affine(&coeffs.ell_coeffs[0]);
        println!(
            "Pairing.ell_by_constant_affine: {} bytes",
            ell_by_constant_affine_script.len()
        );

        // affine mode as well
        let hint = {
            assert_eq!(coeffs.ell_coeffs[0].0, ark_bn254::fq2::Fq2::ONE);

            let mut f1 = f;
            let mut c1new = coeffs.ell_coeffs[0].1;
            c1new.mul_assign_by_fp(&(-p.x / p.y));

            let mut c2new = coeffs.ell_coeffs[0].2;
            c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

            f1.mul_by_034(&coeffs.ell_coeffs[0].0, &c1new, &c2new);
            f1
        };

        let script = script! {
            { fq12_push(f) }
            { utils::from_eval_point(p) }
            { ell_by_constant_affine_script.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_miller_loop_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);

            // projective mode
            let a_prepared = G2Prepared::from(a);
            let a_proj = ark_bn254::G2Projective::from(a);

            let miller_loop = Pairing::miller_loop(&a_prepared, false);
            println!("Pairing.miller_loop: {} bytes", miller_loop.len());

            let hint = Bn254::multi_miller_loop([p], [a_proj]).0;

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { miller_loop.clone() }
                { fq12_push(hint) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            println!("{}", exec_result);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_miller_loop_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);

            // affine mode
            let a_prepared = G2Prepared::from_affine(a);
            let a_affine = a;

            let miller_loop = Pairing::miller_loop(&a_prepared, true);
            println!("Pairing.miller_loop: {} bytes", miller_loop.len());

            let c = Bn254::multi_miller_loop_affine([p], [a_affine]).0;

            let script = script! {
                { utils::from_eval_point(p) }
                { miller_loop.clone() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            println!("{}", exec_result);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_dual_miller_loop_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);
            let q = ark_bn254::G1Affine::rand(&mut prng);
            let a = ark_bn254::g2::G2Affine::rand(&mut prng);
            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let a_proj = ark_bn254::G2Projective::from(a);
            let b_proj = ark_bn254::G2Projective::from(b);

            // projective mode
            let a_prepared = G2Prepared::from(a);
            let b_prepared = G2Prepared::from(b);
            let dual_miller_loop = Pairing::dual_miller_loop(&a_prepared, &b_prepared);
            println!("Pairing.dual_miller_loop: {} bytes", dual_miller_loop.len());

            // projective mode as well
            let c = Bn254::multi_miller_loop([p, q], [a_proj, b_proj]).0;

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
    fn test_dual_millerloop_with_c_wi_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

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

        // random c and wi for test
        let c = ark_bn254::Fq12::rand(&mut prng);
        let c_inv = c.inverse().unwrap();
        let wi = ark_bn254::Fq12::rand(&mut prng);

        // random input points for following two pairings
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let a = ark_bn254::g2::G2Affine::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);

        // projective mode
        let a_proj = ark_bn254::G2Projective::from(a);
        let b_proj = ark_bn254::G2Projective::from(b);

        // benchmark(arkworks): multi miller loop with projective cooordinates of line functions
        let f = Bn254::multi_miller_loop([p, q], [a_proj, b_proj]).0;
        println!("Bn254::multi_miller_loop done!");
        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };
        println!("Accumulated f done!");

        // (projective) coefficients of line functions
        let a_prepared = G2Prepared::from(a);
        let b_prepared = G2Prepared::from(b);
        // test(script): of multi miller loop with projective coordinates of line functions
        let dual_miller_loop_with_c_wi =
            Pairing::dual_miller_loop_with_c_wi(&a_prepared, &b_prepared, false);
        println!(
            "Pairing.dual_miller_loop_with_c_wi(projective): {} bytes",
            dual_miller_loop_with_c_wi.len()
        );

        // input on stack :
        //      p, q, c, c_inv, wi
        // input of script func (parameters):
        //      a_prepared, Vec[(c0, c3, c4)]
        //      b_prepared, Vec[(c0, c3, c4)]
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

    #[test]
    fn test_dual_millerloop_with_c_wi_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // exp = 6x + 2 + p - p^2 = lambda - p^3
        let p_pow3 = &BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
        let lambda = BigUint::from_str(
                        "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
                    ).unwrap();
        let (exp, sign) = if lambda > *p_pow3 {
            (lambda - p_pow3, true)
        } else {
            (p_pow3 - lambda, false)
        };

        // random c and wi just for unit test
        let c = ark_bn254::Fq12::rand(&mut prng);
        let c_inv = c.inverse().unwrap();
        let wi = ark_bn254::Fq12::rand(&mut prng);

        // random input points for following two pairings
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let a = ark_bn254::g2::G2Affine::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);

        // affine mode
        let a_affine = a;
        let b_affine = b;

        // benchmark: multi miller loop with affine cooordinates of line functions
        let f = Bn254::multi_miller_loop_affine([p, q], [a_affine, b_affine]).0;
        println!("Bn254::multi_miller_loop done!");
        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };
        println!("Accumulated f done!");

        // (affine) coefficients of line functions
        let a_prepared = G2Prepared::from_affine(a);
        let b_prepared = G2Prepared::from_affine(b);
        // test(script): of multi miller loop with affine coordinates of line functions
        let dual_miller_loop_with_c_wi_affine =
            Pairing::dual_miller_loop_with_c_wi(&a_prepared, &b_prepared, true);
        println!(
            "Pairing.dual_miller_loop_with_c_wi(affine): {} bytes",
            dual_miller_loop_with_c_wi_affine.len()
        );

        // input on stack :
        //      [-p.x / p.y, 1 / p.y, -q.x / q.y, 1 / q.y, c, c_inv, wi]
        // input of script func (parameters):
        //      a_prepared, Vec[(c0, c3, c4)]
        //      b_prepared, Vec[(c0, c3, c4)]
        let script = script! {
            { utils::from_eval_point(p) }
            // [-p.x / p.y, 1 / p.y]
            { utils::from_eval_point(q) }
            // [-p.x / p.y, 1 / p.y, -q.x / q.y, 1 / q.y]
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }
            // [-p.x / p.y, 1 / p.y, -q.x / q.y, 1 / q.y, c, c_inv, wi]
            { dual_miller_loop_with_c_wi_affine.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        println!("{}", exec_result);
        assert!(exec_result.success);
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

        let script_bytes: Vec<u8> = script! {
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
        }.to_bytes();
        let res = execute_script(Script::from_bytes(script_bytes));
        assert!(res.success);
    }
}
