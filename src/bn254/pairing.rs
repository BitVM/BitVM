#![allow(non_snake_case)]
use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::utils;
use crate::treepp::*;
use ark_ec::bn::BnConfig;

pub struct Pairing;

impl Pairing {
    // input:
    //   p.x
    //   p.y
    pub fn miller_loop(constant: &G2Prepared, is_affine: bool) -> Script {
        let mut constant_iter = constant.ell_coeffs.iter();

        let script = script! {
            { Fq12::push_one() }

            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    { Fq12::square() }
                }

                { Fq2::copy(12) }
                if is_affine {
                    { utils::ell_by_constant_affine(constant_iter.next().unwrap()) }
                } else {
                    { utils::ell_by_constant(constant_iter.next().unwrap()) }
                }

                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq2::copy(12) }
                    if is_affine {
                        { utils::ell_by_constant_affine(constant_iter.next().unwrap()) }
                    } else {
                        { utils::ell_by_constant(constant_iter.next().unwrap()) }
                    }
                }
            }

            { Fq2::copy(12) }
            if is_affine {
                { utils::ell_by_constant_affine(constant_iter.next().unwrap()) }
            } else {
                { utils::ell_by_constant(constant_iter.next().unwrap()) }
            }
            { Fq2::roll(12) }
            if is_affine {
                { utils::ell_by_constant_affine(constant_iter.next().unwrap()) }
            } else {
                { utils::ell_by_constant(constant_iter.next().unwrap()) }
            }
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
                { utils::ell_by_constant(constant_1_iter.next().unwrap()) }

                { Fq2::copy(12) }
                { utils::ell_by_constant(constant_2_iter.next().unwrap()) }

                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq2::copy(14) }
                    { utils::ell_by_constant(constant_1_iter.next().unwrap()) }

                    { Fq2::copy(12) }
                    { utils::ell_by_constant(constant_2_iter.next().unwrap()) }
                }
            }

            { Fq2::copy(14) }
            { utils::ell_by_constant(constant_1_iter.next().unwrap()) }

            { Fq2::copy(12) }
            { utils::ell_by_constant(constant_2_iter.next().unwrap()) }

            { Fq2::roll(14) }
            { utils::ell_by_constant(constant_1_iter.next().unwrap()) }

            { Fq2::roll(12) }
            { utils::ell_by_constant(constant_2_iter.next().unwrap()) }
        };

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        script
    }

    // input on stack (non-fixed) : [P1, P2, c, c_inv, wi]
    // input outside (fixed): L1(Q1), L2(Q2)
    pub fn dual_miller_loop_with_c_wi(
        constant_1: &G2Prepared,
        constant_2: &G2Prepared,
        is_affine: bool,
    ) -> Script {
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
                if is_affine {
                    { utils::ell_by_constant_affine(constant_1_iter.next().unwrap()) }
                } else {
                    { utils::ell_by_constant(constant_1_iter.next().unwrap()) }
                }

                { Fq2::copy(48) }
                if is_affine {
                    { utils::ell_by_constant_affine(constant_2_iter.next().unwrap()) }
                } else {
                    { utils::ell_by_constant(constant_2_iter.next().unwrap()) }
                }

                // update f (add), f = f * add_line_eval
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq2::copy(50) }
                    if is_affine {
                        { utils::ell_by_constant_affine(constant_1_iter.next().unwrap()) }
                    } else {
                        { utils::ell_by_constant(constant_1_iter.next().unwrap()) }
                    }

                    { Fq2::copy(48) }
                    if is_affine {
                        { utils::ell_by_constant_affine(constant_2_iter.next().unwrap()) }
                    } else {
                        { utils::ell_by_constant(constant_2_iter.next().unwrap()) }
                    }
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
            if is_affine {
                { utils::ell_by_constant_affine(constant_1_iter.next().unwrap()) }
            } else {
                { utils::ell_by_constant(constant_1_iter.next().unwrap()) }
            }

            { Fq2::copy(12) }
            if is_affine {
                { utils::ell_by_constant_affine(constant_2_iter.next().unwrap()) }
            } else {
                { utils::ell_by_constant(constant_2_iter.next().unwrap()) }
            }

            // update f (frobenius map): f = f * add_line_eval([-p^2])
            { Fq2::roll(14) }
            if is_affine {
                { utils::ell_by_constant_affine(constant_1_iter.next().unwrap()) }
            } else {
                { utils::ell_by_constant(constant_1_iter.next().unwrap()) }
            }

            { Fq2::roll(12) }
            if is_affine {
                { utils::ell_by_constant_affine(constant_2_iter.next().unwrap()) }
            } else {
                { utils::ell_by_constant(constant_2_iter.next().unwrap()) }
            }
        };

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        script
    }

    /// input on stack:
    ///     [P1, P2, P3, P4, Q4, T4]
    ///     [2,  2,  2,  2,  4,  4] (16 stack elements in total)
    ///     P1, P2, P3, P4 are in affine form, such as P1: (-p1.x / p1.y, 1 / p1.y)
    ///     2 means 2 Fq elements, 4 means 4 fp elements
    ///     Q1, Q2 and Q3 are fixed, Q4 is provided by prover
    ///     T4 is accumulator for Q4, initial T4 = Q4, will do double and add operations for T4

    /// input of parameters:
    ///     [L(Q1), L(Q2), L(Q3), L(Q4)] (line coefficients)
    pub fn quad_miller_loop_affine(constants: Vec<G2Prepared>) -> Script {
        assert_eq!(constants.len(), 4);
        let num_line_groups = constants.len();
        let num_constant = 3;

        let line_coeffs = utils::collect_line_coeffs(constants);
        let num_lines = line_coeffs.len();

        let script = script! {
            { Fq12::push_one() }
            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                // square f
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    { Fq12::square() }
                }
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                // double line
                for j in 0..num_line_groups {
                    // update f with double line evaluation
                    { Fq2::copy((26 - j * 2) as u32) }
                    { utils::ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][0]) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                    // non-fixed part
                    if j == num_constant {
                        // check line coeff is satisfied with T4
                        { Fq12::toaltstack() }
                        { Fq2::copy(2) }
                        { Fq2::copy(2) }
                        { utils::check_tangent_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]

                        // update T4
                        { Fq2::drop() }
                        { utils::affine_double_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        { Fq12::fromaltstack() }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                    }
                }

                // add line
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    for j in 0..num_line_groups {
                        // update f with adding line evaluation
                        { Fq2::copy((26 - j * 2) as u32) }
                        { utils::ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][1]) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                        // non-fixed part
                        if j == num_constant {
                            { Fq12::toaltstack() }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                            { Fq2::copy(2) }
                            { Fq2::copy(2) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), T4(4) | f(12)]
                            { Fq2::copy(10) }
                            { Fq2::copy(10) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), T4(4), Q4(4) | f(12)]
                            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                                { Fq2::neg(0) }
                            }
                            { utils::check_chord_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]

                            // update T4
                            { Fq2::drop() }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2) | f(12)]
                            { Fq2::copy(4) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), Q4.x(2) | f(12)]
                            { utils::affine_add_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                            { Fq12::fromaltstack() }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                        }
                    }
                }
            }

            // First application of the Frobenius map
            for j in 0..num_line_groups {
                // update f with adding line evaluation
                { Fq2::copy((26 - j * 2) as u32) }
                { utils::ell_by_constant_affine(&line_coeffs[num_lines - 2][j][0]) }
                // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                // non-fixed part
                if j == num_constant {
                    { Fq12::toaltstack() }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]

                    // Qx' = Qx.conjugate * beta^{2 * (p - 1) / 6}
                    { Fq2::copy(6) }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x(2) | f(12)]
                    { Fq::neg(0) }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), -Q4.x(2) | f(12)]
                    { Fq2::roll(22) }
                    // Q4.x' = -Q4.x
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), -Q4.x(2), beta_12(2) | f(12)]
                    { Fq2::mul(2, 0) }
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), -Q4.x(2), Q4.x' * beta_12 (2) | f(12)]

                    // Qy' = Qy.conjugate * beta^{3 * (p - 1) / 6}
                    { Fq2::copy(6) }
                    { Fq::neg(0) }
                    { Fq2::roll(22) }
                    { Fq2::mul(2, 0) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12 (2), Q4.y' * beta_13 (2) | f(12)]
                    // phi(Q) = (Qx', Qy')
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4) | f(12)]

                    // check chord line
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4), T4(4) | f(12)]
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4), T4(4), phi(Q)(4) | f(12)]
                    { utils::check_chord_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4) | f(12)]

                    // update T4
                    { Fq2::drop() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q4).x(2) | f(12)]
                    { Fq2::toaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | phi(Q4).x(2), f(12)]
                    { Fq2::drop() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2) | phi(Q4).x(2), f(12)]
                    { Fq2::fromaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), phi(Q4).x(2) | f(12)]
                    { utils::affine_add_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                    { Fq12::fromaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                }
            }

            // Second application of the Frobenius map
            for j in 0..num_line_groups {
                // update f with adding line evaluation by rolling each Pi(2) element to the right(stack top)
                { Fq2::roll((26 - j * 2) as u32) }
                { utils::ell_by_constant_affine(&line_coeffs[num_lines - 1][j][0]) }
                // [beta_22(2), Q4(4), T4(4), f(12)]

                // non-fixed part(Q4)
                if j == num_constant {
                    { Fq12::toaltstack() }
                    // [beta_22(2), Q4(4), T4(4) | f(12)]

                    { Fq2::roll(8) }
                    // [Q4(4), T4(4), beta_22(2) | f(12)]
                    { Fq2::roll(8) }
                    // [Q4.y(2), T4(4), beta_22(2), Q4.x(2) | f(12)]
                    { Fq2::mul(2, 0) }
                    // [Q4.y(2), T4(4), beta_22(2) * Q4.x(2) | f(12)]
                    // Qx' = Qx * beta^{2 * (p^2 - 1) / 6}
                    // [Q4.y(2), T4(4), Qx'(2) | f(12)]
                    { Fq2::roll(6) }
                    // [T4(4), Qx'(2), Q4.y(2) | f(12)]
                    // phi(Q)^2 = (Qx', Qy)
                    // [T4(4), phi(Q4)^2 | f(12)]

                    // check whether the chord line through T4 and phi(Q4)^2
                    { utils::check_chord_line(line_coeffs[num_lines - 1][j][0].1, line_coeffs[num_lines - 1][j][0].2) }
                    // [ | f(12)]
                    { Fq12::fromaltstack() }
                    // [f(12)]
                }
            }
        };
        script
    }


    // refer algorithm 9 of https://eprint.iacr.org/2024/640.pdf
    // four pairings in total, where three of them is fixed on G2, only one is non-fixed on G2 (specially for groth16 verifier for now)

    /// input on stack:
    ///     stack elements:           [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c,  c_inv, wi, T4]
    ///     amount of Fq per element: [2,  2,  2,  2,  2,  2,  4,  4,  12, 12, 12, 4], number is the amount of Fq elements
    ///     stack index:    [58, 56, 54, 52, 50, 48, 44, 40, 28, 16, 4,  0]
    ///     P1, P2, P3, P4 are in affine form, such as P1: (-p1.x / p1.y, 1 / p1.y)
    ///     Q1, Q2 and Q3 are fixed, Q4 is provided by prover
    ///     T4 is accumulator for Q4, initial T4 = Q4, will do double and add operations for T4

    /// input of parameters:
    ///     [L(Q1), L(Q2), L(Q3), L(Q4)] (line coefficients)
    pub fn quad_miller_loop_affine_with_c_wi(constants: Vec<G2Prepared>) -> Script {
        assert_eq!(constants.len(), 4);
        let num_line_groups = constants.len();
        let num_constant = 3;

        let line_coeffs = utils::collect_line_coeffs(constants);
        let num_lines = line_coeffs.len();

        let script = script! {
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4)]
            // 1. f = c_inv
            { Fq12::copy(16) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12)]

            // ATE_LOOP_COUNT len: 65
            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                // square f
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    { Fq12::square() }
                }
                // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12)]

                // double line
                for j in 0..num_line_groups {
                    // copy P_j(p1, p2, p3, p4) to stack
                    { Fq2::copy((26 + 36 - j * 2) as u32) }
                    // update f with double line evaluation
                    { utils::ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][0]) }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12)]

                    // non-fixed part
                    if j == num_constant {
                        // check line coeff is satisfied with T4
                        { Fq12::toaltstack() }
                        // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4) | f(12)]
                        { Fq2::copy(2) }
                        { Fq2::copy(2) }
                        // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), T4(4) | f(12)]
                        { utils::check_tangent_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4) | f(12)]

                        // update T4
                        // drop T4.y, leave T4.x
                        { Fq2::drop() }
                        // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4.x(2) | f(12)]
                        // update f with double line evaluation
                        { utils::affine_double_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4) | f(12)]
                        { Fq12::fromaltstack() }
                        // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12)]
                    }
                }

                // update c_inv
                // f = f * c_inv, if digit == 1
                // f = f * c, if digit == -1
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
                    // copy c_inv
                    { Fq12::copy(28) }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12), c_inv(12)]
                    // f = f * c_inv
                    { Fq12::mul(12, 0) }
                } else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    // copy c
                    { Fq12::copy(40) }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12), c(12)]
                    // f = f * c
                    { Fq12::mul(12, 0) }
                }
                // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12)]

                // add line
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    for j in 0..num_line_groups {
                        // copy P_j(p1, p2, p3, p4) to stack
                        { Fq2::copy((26 + 36 - j * 2) as u32) }
                        // update f with adding line evaluation
                        { utils::ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][1]) }
                        // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12)]

                        // non-fixed part
                        if j == num_constant {
                            { Fq12::toaltstack() }
                            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4) | f(12)]

                            // copy T4
                            { Fq2::copy(2) }
                            { Fq2::copy(2) }
                            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), T4(4) | f(12)]

                            // copy Q4
                            { Fq2::copy(10 + 36) }
                            { Fq2::copy(10 + 36) }
                            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), T4(4), Q4(4) | f(12)]
                            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                                { Fq2::neg(0) }
                            }
                            { utils::check_chord_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4) | f(12)]

                            // update T4
                            // drop T4.y, leave T4.x
                            { Fq2::drop() }
                            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4.x(2) | f(12)]
                            // copy Q4.x
                            { Fq2::copy(4) }
                            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4.x(2), Q4.x(2) | f(12)]
                            // add line then T updated
                            { utils::affine_add_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4) | f(12)]
                            { Fq12::fromaltstack() }
                            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), c_inv(12), wi(12), T4(4), f(12)]
                        }
                    }
                }
            }

            // update f: f = f * c_inv^p * c^{p^2}
            { Fq12::roll(28) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), wi(12), T4(4), f(12), c_inv(12)]
            { Fq12::frobenius_map(1) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), wi(12), T4(4), f(12), c_inv^p(12)]
            { Fq12::mul(12, 0) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), c(12), wi(12), T4(4), f(12)]
            { Fq12::roll(28) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), wi(12), T4(4), f(12), c(12)]
            { Fq12::frobenius_map(2) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), wi(12), T4(4), f(12), c^{p^2}(12)]
            { Fq12::mul(12, 0) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), wi(12), T4(4), f(12)]

            // scale f: f = f * wi
            { Fq12::roll(16) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), wi(12)]
            { Fq12::mul(12, 0) }
            // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

            // First application of the Frobenius map
            for j in 0..num_line_groups {
                // copy P_j(p1, p2, p3, p4) to stack
                { Fq2::copy((26 - j * 2) as u32) }
                // update f with adding line evaluation
                // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P_j(2)]
                { utils::ell_by_constant_affine(&line_coeffs[num_lines - 2][j][0]) }
                // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                // non-fixed part
                if j == num_constant {
                    { Fq12::toaltstack() }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]

                    // Qx' = Qx.conjugate * beta^{2 * (p - 1) / 6}
                    { Fq2::copy(6) }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x(2) | f(12)]
                    { Fq::neg(0) }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), -Q4.x(2) | f(12)]
                    { Fq2::roll(22) }
                    // Q4.x' = -Q4.x
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x'(2), beta_12(2) | f(12)]
                    { Fq2::mul(2, 0) }
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12 (2) | f(12)]

                    // Qy' = Qy.conjugate * beta^{3 * (p - 1) / 6}
                    // copy Q4.y
                    { Fq2::copy(6) }
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), -Q4.x' * beta_12 (2), Q4.y(2) | f(12)]
                    // Q4.y' = -Q4.y
                    { Fq::neg(0) }
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), -Q4.x' * beta_12 (2), Q4.y'(2) | f(12)]
                    { Fq2::roll(22) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), -Q4.x' * beta_12 (2), Q4.y'(2), beta_13(2) | f(12)]
                    { Fq2::mul(2, 0) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12 (2), Q4.y' * beta_13 (2) | f(12)]
                    // phi(Q) = (Q4.x' * beta_12 (2), Q4.y' * beta_13 (2))
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4) | f(12)]

                    // check chord line
                    // copy T4
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4), T4(4) | f(12)]
                    // copy phi(Q)
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4), T4(4), phi(Q)(4) | f(12)]
                    { utils::check_chord_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4) | f(12)]

                    // update T4
                    // drop phi(Q).y
                    { Fq2::drop() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q4).x(2) | f(12)]
                    { Fq2::toaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | phi(Q4).x(2), f(12)]
                    // drop T4.y
                    { Fq2::drop() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2) | phi(Q4).x(2), f(12)]
                    { Fq2::fromaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), phi(Q4).x(2) | f(12)]
                    { utils::affine_add_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                    { Fq12::fromaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                }
            }

            // Second application of the Frobenius map
            for j in 0..num_line_groups {
                // update f with adding line evaluation by rolling each Pi(2) element to the right(stack top)
                // roll P_j(p1, p2, p3, p4) to stack top
                { Fq2::roll((26 - j * 2) as u32) }
                // update f with adding line evaluation
                { utils::ell_by_constant_affine(&line_coeffs[num_lines - 1][j][0]) }
                // [beta_22(2), Q4(4), T4(4), f(12)]

                // non-fixed part(Q4)
                if j == num_constant {
                    { Fq12::toaltstack() }
                    // [beta_22(2), Q4(4), T4(4) | f(12)]

                    { Fq2::roll(8) }
                    // [Q4(4), T4(4), beta_22(2) | f(12)]
                    { Fq2::roll(8) }
                    // [Q4.y(2), T4(4), beta_22(2), Q4.x(2) | f(12)]
                    { Fq2::mul(2, 0) }
                    // [Q4.y(2), T4(4), beta_22(2) * Q4.x(2) | f(12)]
                    // Qx' = Qx * beta^{2 * (p^2 - 1) / 6}
                    // [Q4.y(2), T4(4), Qx'(2) | f(12)]
                    { Fq2::roll(6) }
                    // [T4(4), Qx'(2), Q4.y(2) | f(12)]
                    // phi(Q)^2 = (Qx', Qy)
                    // [T4(4), phi(Q4)^2 | f(12)]

                    // check whether the chord line through T4 and phi(Q4)^2
                    { utils::check_chord_line(line_coeffs[num_lines - 1][j][0].1, line_coeffs[num_lines - 1][j][0].2) }
                    // [ | f(12)]
                    { Fq12::fromaltstack() }
                    // [f(12)]
                }
            }
        };
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
                    { utils::ell_by_constant(constant_iters[j].next().unwrap()) }
                }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

                // non-fixed (non-constant part) P4
                { Fq2::copy(/* offset_P */(46 + 12) as u32) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f, P4]
                // roll T, and double line with T (projective coordinates)
                { Fq6::roll(/* offset_T */(12 + 2) as u32) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4]
                { utils::double_line() }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, (,,)]
                { Fq6::roll(6) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,), T4]
                { Fq6::toaltstack() }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,) | T4]
                // line evaluation and update f
                { Fq2::roll(6) }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, (,,), P4 | T4]
                { utils::ell() }
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
                        { utils::ell_by_constant(constant_iters[j].next().unwrap()) }
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
                    { utils::add_line_with_flag(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, (,,)]
                    { Fq6::roll(6) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,), T4]
                    { Fq6::toaltstack() }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,) | T4]
                    // line evaluation and update f
                    { Fq2::roll(6) }
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, (,,), P4 | T4]
                    // { Pairing::ell_by_non_constant() }
                    { utils::ell() }
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
            // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, wi, T4, f, c^{p^2}]
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
                { utils::ell_by_constant(constant_iters[j].next().unwrap()) }
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
            { utils::add_line_with_flag(true) }
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, (,,)]
            { Fq6::roll(6) }
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, (,,), T4]
            { Fq6::toaltstack() }
            // [beta_22, P1, P2, P3, P4, Q4, f, P4, (,,) | T4]

            // line evaluation and update f
            { Fq2::roll(6) }
            // [beta_22, P1, P2, P3, P4, Q4, f, (,,), P4 | T4]
            { utils::ell() }
            // [beta_22, P1, P2, P3, P4, Q4, f | T4]
            { Fq6::fromaltstack() }
            { Fq12::roll(6) }
            // [beta_22, P1, P2, P3, P4, Q4, T4, f]

            /////////////////////////////////////// 6. two-times frobenius map on fixed and non-fixed lines
            // 6.1 fixed part, P1, P2, P3
            for j in 0..num_constant {
                { Fq2::roll((28 - j * 2) as u32) }
                { utils::ell_by_constant(constant_iters[j].next().unwrap()) }
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
            { utils::add_line_with_flag(true) }
            // [f, P4, T4, (,,)]
            { Fq6::roll(6) }
            // [f, P4, (,,), T4]
            { Fq6::drop() }
            // [f, P4, (,,)]
            // line evaluation and update f
            { Fq2::roll(6) }
            // [f, (,,), P4]
            { utils::ell() }
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
    use crate::bn254::utils::{self, fq12_push, fq2_push};
    use crate::{execute_script_without_stack_limit, treepp::*};
    use ark_bn254::g2::G2Affine;
    use ark_bn254::Bn254;

    use ark_ec::pairing::Pairing as _;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::AffineRepr;
    use ark_ff::{AdditiveGroup, Field};
    use ark_std::{test_rng, UniformRand};
    use num_bigint::BigUint;
    use num_traits::Num;
    use num_traits::One;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

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

            // projective mode
            let Q1_proj = ark_bn254::G2Projective::from(Q1);
            let Q2_proj = ark_bn254::G2Projective::from(Q2);
            let Q3_proj = ark_bn254::G2Projective::from(Q3);
            let Q4_proj = ark_bn254::G2Projective::from(Q4);

            let T4 = Q4.into_group();

            let quad_miller_loop_with_c_wi = Pairing::quad_miller_loop_with_c_wi(
                &[Q1_prepared, Q2_prepared, Q3_prepared].to_vec(),
            );
            println!(
                "Pairing.quad_miller_loop_with_c_wi: {} bytes",
                quad_miller_loop_with_c_wi.len()
            );

            let f =
                Bn254::multi_miller_loop([P1, P2, P3, P4], [Q1_proj, Q2_proj, Q3_proj, Q4_proj]).0;
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
    fn test_quad_miller_loop_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let p1 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);

        let q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q1_prepared = G2Prepared::from_affine(q1);
        let q2_prepared = G2Prepared::from_affine(q2);
        let q3_prepared = G2Prepared::from_affine(q3);
        let q4_prepared = G2Prepared::from_affine(q4);

        let t4 = q4;

        let quad_miller_loop_affine_script = Pairing::quad_miller_loop_affine(
            [q1_prepared, q2_prepared, q3_prepared, q4_prepared].to_vec(),
        );
        println!(
            "Pairing.quad_miller_loop: {} bytes",
            quad_miller_loop_affine_script.len()
        );

        let hint = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        println!("Bn254::multi_miller_loop_affine done!");

        // [beta_12, beta_13, beta_22, p1, p2, p3, p4, q4, t4]: p1-p4: (-p.x / p.y, 1 / p.y)
        let script = script! {
            { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

            { utils::from_eval_point(p1) }
            { utils::from_eval_point(p2) }
            { utils::from_eval_point(p3) }
            { utils::from_eval_point(p4) }

            { fq2_push(q4.x) }
            { fq2_push(q4.y) }

            { fq2_push(t4.x) }
            { fq2_push(t4.y) }

            { quad_miller_loop_affine_script.clone() }

            { fq12_push(hint) }
            { Fq12::equalverify() }

            OP_TRUE
        };
        let exec_result = execute_script_without_stack_limit(script);
        if !exec_result.success {
            println!(
                "Remaining script size: {}, last opcode: {}",
                exec_result.remaining_script.len(),
                exec_result.last_opcode.unwrap().to_string()
            );
        }
        assert!(exec_result.success);
    }

    #[test]
    fn test_quad_miller_loop_affine_with_c_wi() {
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
        // random c and wi
        let c = ark_bn254::Fq12::rand(&mut prng);
        let c_inv = c.inverse().unwrap();
        let wi = ark_bn254::Fq12::rand(&mut prng);

        let p1 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);

        let q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q1_prepared = G2Prepared::from_affine(q1);
        let q2_prepared = G2Prepared::from_affine(q2);
        let q3_prepared = G2Prepared::from_affine(q3);
        let q4_prepared = G2Prepared::from_affine(q4);

        let t4 = q4;

        let quad_miller_loop_affine_script = Pairing::quad_miller_loop_affine_with_c_wi(
            [q1_prepared, q2_prepared, q3_prepared, q4_prepared].to_vec(),
        );
        println!(
            "Pairing.quad_miller_loop: {} bytes",
            quad_miller_loop_affine_script.len()
        );

        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        println!("Bn254::multi_miller_loop_affine done!");

        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };

        // [beta_12, beta_13, beta_22, p1, p2, p3, p4, q4, t4]: p1-p4: (-p.x / p.y, 1 / p.y)
        let script = script! {
            // beta_12
            { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }
            // beta_13
            { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }
            // beta_22
            { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

            // p1, p2, p3, p4
            { utils::from_eval_point(p1) }
            { utils::from_eval_point(p2) }
            { utils::from_eval_point(p3) }
            { utils::from_eval_point(p4) }

            // q4
            { fq2_push(q4.x) }
            { fq2_push(q4.y) }

            // c, c_inv, wi
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }

            // t4
            { fq2_push(t4.x) }
            { fq2_push(t4.y) }

            { quad_miller_loop_affine_script.clone() }

            { fq12_push(hint) }

            { Fq12::equalverify() }

            OP_TRUE
        };
        let exec_result = execute_script_without_stack_limit(script);
        if !exec_result.success {
            println!(
                "Remaining script size: {}, last opcode: {}",
                exec_result.remaining_script.len(),
                exec_result.last_opcode.unwrap().to_string()
            );
        }
        assert!(exec_result.success);
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
