use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::utils;
use crate::treepp::*;
use ark_ec::bn::BnConfig;
pub struct QuadPairing;

impl QuadPairing {
    // input on stack:
    // - beta_12(2)
    // - beta_13(2)
    // - beta_22(2), above three constants are used to compute one or two times of frobenius map of point of G2 point Q
    // - P1'(2), a map of point G1 point P1, say (x, y) -> (-x / y, 1 / y)
    // - P2'(2), similar with P1'
    // - P3'(2), similar with P1'
    // - P4'(2), similar with P1'
    // - Q4(4), non-fixed G2 point Q4
    // - T4(4), accumulator of Q4, who is initialized with Q4
    //
    // input of parameters:
    // - line_prepared, which is a vector of line coefficients of G2 points, say Q1, Q2, Q3, Q4
    //
    // output on stack:
    // - [ f ], which is the final accumulated line evaluations of quadruple miller loop with one non-fixed point Q4
    pub fn quad_miller_loop_affine(line_prepared: Vec<G2Prepared>) -> Script {
        assert_eq!(line_prepared.len(), 4);
        let num_const_plus_non_const = line_prepared.len();

        let line_coeffs = utils::collect_line_coeffs(line_prepared);
        let num_constant = 3;
        let num_lines = line_coeffs.len();

        let script = script! {
            { Fq12::push_one() }
            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    { Fq12::square() }
                }
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                // double line
                for j in 0..num_const_plus_non_const {
                    { Fq2::copy((26 - j * 2) as u32) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P_i(2)]

                    { utils::ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][0]) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                    // non-constant part
                    if j == num_constant {
                        /////////// check line coeff is satisfied with T4
                        // copy T4
                        { Fq2::copy(14) }
                        { Fq2::copy(14) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), T4(4)]
                        { utils::check_tangent_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                        ///////////// update T4 (double)
                        { Fq12::toaltstack() }
                        { Fq2::drop() }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x | f(12)]
                        { utils::affine_double_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                        { Fq12::fromaltstack() }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                    }
                }

                // add line
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    for j in 0..num_const_plus_non_const {
                        ////////////////////////////////// constant part
                        { Fq2::copy((26 - j * 2) as u32) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P_i(2)]
                        { utils::ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][1]) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                        ///////////////////////////////// non-constant part
                        if j == num_constant {
                            ////////////////// check whether the line through T4 and Q4 is chord
                            // copy Q4, T4
                            { Fq2::copy(18) }
                            { Fq2::copy(18) }
                            { Fq2::copy(18) }
                            { Fq2::copy(18) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), Q4(4), T4(4)]
                            { Fq2::roll(6)}
                            { Fq2::roll(6)}
                            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                                { Fq2::neg(0) }
                            }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), T4(4), Q4(4)]
                            { utils::check_chord_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                            /////////////////// update T4
                            { Fq12::toaltstack() }
                            { Fq2::drop() }
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

            // one-time of frobenius map
            for j in 0..num_const_plus_non_const {
                /////////////////////////////////////// constant part
                { Fq2::copy((26 - j * 2) as u32) }
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P_i(2)]
                { utils::ell_by_constant_affine(&line_coeffs[num_lines - 2][j][0]) }
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                ////////////////////////////////////// non-constant part
                if j == num_constant {
                    //////////////////// phi(Q4)
                    { Fq12::toaltstack() }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                    ////// Qx.conjugate * beta^{2 * (p - 1) / 6}
                    { Fq2::copy(6) }
                    { Fq::neg(0) }
                    // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' | f(12)]
                    { Fq2::roll(22) }
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x', beta_12(2) | f(12)]
                    { Fq2::mul(2, 0) }
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12(2) | f(12)]

                    ////// Qy.conjugate * beta^{3 * (p - 1) / 6}
                    { Fq2::copy(6) }
                    { Fq::neg(0) }
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12(2), Q4.y'(2) | f(12)]
                    { Fq2::roll(22) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12(2), Q4.y'(2), beta_13(2) | f(12)]
                    { Fq2::mul(2, 0) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12(2), Q4.y' * beta_13(2) | f(12)]
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4'(4) | f(12)]

                    ////////////////// check whether the chord line is through T4 and phi(Q4) or not
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    { utils::check_chord_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4'(4) | f(12)]

                    /////////////////// update T4
                    { Fq2::drop() }
                    { Fq2::toaltstack() }
                    { Fq2::drop() }
                    { Fq2::fromaltstack() }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x, Q4'.x | f(12)]
                    { utils::affine_add_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                    { Fq12::fromaltstack() }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                }
            }

            // two-times of frobenius map
            for j in 0..num_const_plus_non_const {
                //////////////////////////// constant part
                { Fq2::roll((26 - j * 2) as u32) }
                { utils::ell_by_constant_affine(&line_coeffs[num_lines - 1][j][0]) }
                // [beta_22(2), Q4(4), T4(4), f(12)]

                /////////////////////////// non-constant part
                if j == num_constant {
                    ///////////////////// phi(Q)^2
                    { Fq12::toaltstack() }
                    // [beta_22(2), Q4(4), T4(4) | f(12)]

                    // Qx * beta^{2 * (p^2 - 1) / 6}
                    { Fq2::roll(6) }
                    { Fq2::roll(8) }
                    // [Q4.y(2), T4(4), Q4.x(2), beta_22(2) | f(12)]
                    { Fq2::mul(2, 0) }
                    // [Q4.y(2), T4(4), Q4.x * beta_22(2) | f(12)]
                    { Fq2::roll(6) }
                    // [Q4.y(2), T4(4), Q4.x * beta_22(2), Q4.y | f(12)]
                    // [T4(4), Q4' | f(12) ]
                    { utils::check_chord_line(line_coeffs[num_lines - 1][j][0].1, line_coeffs[num_lines - 1][j][0].2) }
                    { Fq12::fromaltstack() }
                    // [ f(12) ]
                }
            }
        };

        script
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bn254::{
            ell_coeffs::G2Prepared,
            fq12::Fq12,
            quad_pairing::QuadPairing,
            utils::{self, fq12_push, fq2_push},
        },
        execute_script_without_stack_limit,
    };
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing as _;
    use ark_ff::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

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

        let quad_miller_loop_affine = QuadPairing::quad_miller_loop_affine(
            [q1_prepared, q2_prepared, q3_prepared, q4_prepared].to_vec(),
        );
        println!(
            "Pairing.quad_miller_loop_affine: {} bytes",
            quad_miller_loop_affine.len()
        );

        let hint = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        println!("Bn254::multi_miller_loop_affine done!");

        // [beta_12, beta_13, beta_22, p1', p2', p3', p4', q4, t4]
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

            { quad_miller_loop_affine.clone() }

            { fq12_push(hint) }
            { Fq12::equalverify() }

            OP_TRUE
        };
        let exec_result = execute_script_without_stack_limit(script);
        // for debuging purpose only
        if !exec_result.success {
            println!(
                "Remaining script size: {}, last op code: {}",
                exec_result.remaining_script.len(),
                exec_result.last_opcode.unwrap()
            );
        }
        assert!(exec_result.success);
    }
}
